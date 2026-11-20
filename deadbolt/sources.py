"""Where text comes from: working tree, staged index, git history, archives
and `docker save` / OCI image tarballs. All local, all offline."""

from __future__ import annotations

import fnmatch
import io
import os
import re
import subprocess
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from .models import Location

DEFAULT_MAX_BYTES = 2 * 1024 * 1024
MAX_NESTED_BYTES = 512 * 1024 * 1024

SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", ".tox", "dist", "build", ".next", ".terraform", "target", ".gradle", ".idea",
}
SKIP_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".bz2", ".xz", ".7z",
    ".woff", ".woff2", ".ttf", ".otf", ".mp3", ".mp4", ".mov", ".wav", ".so", ".dylib", ".dll",
    ".exe", ".bin", ".class", ".jar", ".pyc", ".o", ".a", ".lock", ".svg", ".min.js", ".map",
    ".parquet", ".onnx", ".safetensors", ".pt", ".gguf",
}
ARCHIVE_EXT = (".tar", ".tar.gz", ".tgz", ".oci", ".tar.zst")


@dataclass
class Blob:
    location: Location
    text: str


def load_ignore(root: Path) -> list[str]:
    f = root / ".deadboltignore"
    if not f.is_file():
        return []
    return [ln.strip() for ln in f.read_text("utf-8", "replace").splitlines() if ln.strip() and not ln.startswith("#")]


def ignored(rel: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(rel, p.rstrip("/") + "/*") for p in patterns)


def decode(data: bytes) -> str | None:
    if b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", "replace")


def _skip_name(name: str) -> bool:
    low = name.lower()
    return any(low.endswith(e) for e in SKIP_EXT) and not low.endswith(ARCHIVE_EXT)


def iter_files(root: Path, max_bytes: int = DEFAULT_MAX_BYTES, extra_ignore: list[str] | None = None) -> Iterator[Path]:
    root = root.resolve()
    patterns = load_ignore(root) + (extra_ignore or [])
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for fn in sorted(filenames):
            p = Path(dirpath) / fn
            rel = p.relative_to(root).as_posix()
            if patterns and ignored(rel, patterns):
                continue
            if p.is_symlink():
                continue
            is_archive = fn.lower().endswith(ARCHIVE_EXT)
            if _skip_name(fn) and not is_archive:
                continue
            try:
                size = p.stat().st_size
            except OSError:
                continue
            if size > (MAX_NESTED_BYTES if is_archive else max_bytes):
                continue
            yield p


def read_blob(path: Path, rel: str) -> Iterator[Blob]:
    if path.name.lower().endswith(ARCHIVE_EXT):
        yield from iter_archive(path, rel)
        return
    try:
        data = path.read_bytes()
    except OSError:
        return
    text = decode(data)
    if text is not None:
        yield Blob(Location(path=rel), text)


# ------------------------------------------------------------- tar / docker
def _walk_tar(tf: tarfile.TarFile, prefix: str, layer: str | None, origin: str, depth: int) -> Iterator[Blob]:
    for member in tf:
        if not member.isfile() or member.size == 0:
            continue
        name = member.name.lstrip("./")
        # OCI blobs and docker-save layer.tar entries are themselves tarballs
        looks_layer = name.endswith(("layer.tar", ".tar", ".tar.gz", ".tgz")) or name.startswith("blobs/sha256/")
        if looks_layer and depth < 3 and member.size <= MAX_NESTED_BYTES:
            fh = tf.extractfile(member)
            if fh is None:
                continue
            data = fh.read()
            try:
                inner = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
            except (tarfile.TarError, OSError, EOFError):
                inner = None
            if inner is not None:
                layer_id = name.split("/")[-1] if name.startswith("blobs/") else name.split("/")[0]
                with inner:
                    yield from _walk_tar(inner, prefix, layer_id[:64], "docker-layer", depth + 1)
                continue
            text = decode(data[:DEFAULT_MAX_BYTES])
            if text is not None and not name.startswith("blobs/"):
                yield Blob(Location(path=f"{prefix}!/{name}", origin=origin, layer=layer), text)
            continue
        if _skip_name(name) or member.size > DEFAULT_MAX_BYTES:
            continue
        fh = tf.extractfile(member)
        if fh is None:
            continue
        text = decode(fh.read())
        if text is not None:
            yield Blob(Location(path=f"{prefix}!/{name}", origin=origin, layer=layer), text)


def iter_archive(path: Path, rel: str) -> Iterator[Blob]:
    try:
        tf = tarfile.open(path, mode="r:*")
    except (tarfile.TarError, OSError, EOFError):
        return
    with tf:
        yield from _walk_tar(tf, rel, None, "archive", 0)


# --------------------------------------------------------------------- git
def _git(root: Path, *args: str) -> str:
    res = subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True, errors="replace", check=False
    )
    if res.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {res.stderr.strip()}")
    return res.stdout


def iter_staged(root: Path) -> Iterator[Blob]:
    names = _git(root, "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z").split("\0")
    patterns = load_ignore(root)
    for name in filter(None, names):
        if _skip_name(name) or ignored(name, patterns):
            continue
        res = subprocess.run(["git", "-C", str(root), "show", f":{name}"], capture_output=True, check=False)
        if res.returncode == 0 and (text := decode(res.stdout[:DEFAULT_MAX_BYTES])) is not None:
            yield Blob(Location(path=name, origin="staged"), text)


_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def iter_history(root: Path, max_commits: int = 1000) -> Iterator[Blob]:
    """Yield only the *added* lines of each commit, grouped per file per commit,
    with real line numbers reconstructed from hunk headers."""
    out = _git(root, "log", "--all", "-p", "-U0", "--no-color", "--no-ext-diff",
               f"--max-count={max_commits}", "--format=__DEADBOLT_COMMIT__ %H")
    patterns = load_ignore(root)
    commit = path = None
    lines: list[str] = []
    first_line = 1
    expected = 1

    def flush() -> Iterator[Blob]:
        if commit and path and lines and not _skip_name(path) and not ignored(path, patterns):
            yield Blob(Location(path=path, line=first_line, origin="git-history", commit=commit), "\n".join(lines))

    for raw in out.splitlines():
        if raw.startswith("__DEADBOLT_COMMIT__ "):
            yield from flush()
            commit, path, lines = raw.split(" ", 1)[1], None, []
        elif raw.startswith("+++ "):
            yield from flush()
            target = raw[4:]
            path = None if target == "/dev/null" else target[2:] if target.startswith("b/") else target
            lines = []
        elif m := _HUNK.match(raw):
            start = int(m.group(1))
            if lines and start != expected:
                # non-contiguous hunk: emit what we have, start a new block
                yield from flush()
                lines = []
            if not lines:
                first_line = start
            expected = start
        elif raw.startswith("+") and not raw.startswith("+++"):
            lines.append(raw[1:])
            expected += 1
    yield from flush()
