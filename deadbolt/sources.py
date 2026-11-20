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


def parse_ignore(text: str) -> list[str]:
    return [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]


def load_ignore(root: Path) -> list[str]:
    f = root / ".deadboltignore"
    if not f.is_file():
        return []
    return parse_ignore(f.read_text("utf-8", "replace"))


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
    def walk_error(error: OSError) -> None:
        raise RuntimeError("Incomplete scan: directory could not be read") from error

    for dirpath, dirnames, filenames in os.walk(root, onerror=walk_error):
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
            except OSError as exc:
                raise RuntimeError(f"Incomplete scan: cannot inspect {rel}") from exc
            if size > (MAX_NESTED_BYTES if is_archive else max_bytes):
                raise RuntimeError(f"Incomplete scan: file exceeds size limit: {rel}")
            yield p


def read_blob(path: Path, rel: str) -> Iterator[Blob]:
    if path.name.lower().endswith(ARCHIVE_EXT):
        yield from iter_archive(path, rel)
        return
    try:
        with path.open("rb") as source:
            data = source.read(DEFAULT_MAX_BYTES + 1)
        if len(data) > DEFAULT_MAX_BYTES:
            raise RuntimeError(f"Incomplete scan: file exceeds size limit: {rel}")
    except OSError as exc:
        raise RuntimeError(f"Incomplete scan: cannot read {rel}") from exc
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
        if looks_layer and (depth >= 3 or member.size > MAX_NESTED_BYTES):
            raise RuntimeError(f"Incomplete scan: archive depth or size limit: {prefix}")
        if looks_layer:
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
            if len(data) > DEFAULT_MAX_BYTES:
                raise RuntimeError(f"Incomplete scan: archive blob exceeds size limit: {prefix}")
            text = decode(data)
            if name.startswith("blobs/") and text is not None:
                yield Blob(Location(path=f"{prefix}!/{name}", origin=origin, layer=layer), text)
            else:
                raise RuntimeError(f"Incomplete scan: unreadable nested archive in {prefix}")
            continue
        if _skip_name(name):
            continue
        if member.size > DEFAULT_MAX_BYTES:
            raise RuntimeError(f"Incomplete scan: archive member exceeds size limit: {prefix}")
        fh = tf.extractfile(member)
        if fh is None:
            continue
        text = decode(fh.read())
        if text is not None:
            yield Blob(Location(path=f"{prefix}!/{name}", origin=origin, layer=layer), text)


def iter_archive(path: Path, rel: str) -> Iterator[Blob]:
    try:
        if path.stat().st_size > MAX_NESTED_BYTES:
            raise RuntimeError(f"Incomplete scan: archive exceeds size limit: {rel}")
        with tarfile.open(path, mode="r:*") as tf:
            yield from _walk_tar(tf, rel, None, "archive", 0)
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise RuntimeError(f"Incomplete scan: cannot read archive {rel}") from exc


# --------------------------------------------------------------------- git
def _git(root: Path, *args: str) -> str:
    res = subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True, errors="replace", check=False
    )
    if res.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {res.stderr.strip()}")
    return res.stdout


def iter_staged(root: Path, extra_ignore: list[str] | None = None) -> Iterator[Blob]:
    root = Path(_git(root, "rev-parse", "--show-toplevel").strip())
    names = _git(root, "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z").split("\0")
    patterns = list(extra_ignore or [])
    # The policy for a staged scan comes from the same index snapshot.
    if _git(root, "ls-files", "--cached", "--", ".deadboltignore").strip():
        patterns += parse_ignore(_git(root, "show", ":.deadboltignore"))
    if _git(root, "ls-files", "--unmerged").strip():
        raise RuntimeError("Incomplete scan: resolve unmerged index entries first")
    for name in filter(None, names):
        if _skip_name(name) or ignored(name, patterns):
            continue
        is_archive = name.lower().endswith(ARCHIVE_EXT)
        size = int(_git(root, "cat-file", "-s", f":{name}").strip())
        if size > (MAX_NESTED_BYTES if is_archive else DEFAULT_MAX_BYTES):
            raise RuntimeError(f"Incomplete scan: staged file exceeds size limit: {name}")
        res = subprocess.run(["git", "-C", str(root), "show", f":{name}"], capture_output=True, check=False)
        if res.returncode:
            raise RuntimeError(f"Incomplete scan: cannot read staged file {name}")
        if is_archive:
            try:
                with tarfile.open(fileobj=io.BytesIO(res.stdout), mode="r:*") as tf:
                    yield from _walk_tar(tf, name, None, "staged", 0)
            except (tarfile.TarError, OSError, EOFError) as exc:
                raise RuntimeError(f"Incomplete scan: cannot read staged archive {name}") from exc
        elif (text := decode(res.stdout)) is not None:
            yield Blob(Location(path=name, origin="staged"), text)


_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def iter_history(root: Path, max_commits: int = 1000) -> Iterator[Blob]:
    """Yield only the *added* lines of each commit, grouped per file per commit,
    with real line numbers reconstructed from hunk headers."""
    total = int(_git(root, "rev-list", "--count", "--all").strip())
    if max_commits < 1 or total > max_commits:
        raise RuntimeError(f"Incomplete history scan: {total} commits exceed --max-commits={max_commits}")
    out = _git(root, "log", "--all", "-p", "-U0", "--no-color", "--no-ext-diff",
               f"--max-count={max_commits}", "--format=__DEADBOLT_COMMIT__ %H")
    patterns = load_ignore(root)
    commit = path = None
    lines: list[str] = []
    first_line = 1
    expected = 1

    def flush() -> Iterator[Blob]:
        if commit and path and lines and not _skip_name(path) and not ignored(path, patterns):
            if path.lower().endswith((".json", ".toml")):
                # Config parsers need a complete document when a commit changes one field.
                size = int(_git(root, "cat-file", "-s", f"{commit}:{path}").strip())
                if size > DEFAULT_MAX_BYTES:
                    raise RuntimeError(f"Incomplete scan: historical config exceeds size limit: {path}")
                text = _git(root, "show", f"{commit}:{path}")
                yield Blob(Location(path=path, origin="git-history", commit=commit), text)
            else:
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
