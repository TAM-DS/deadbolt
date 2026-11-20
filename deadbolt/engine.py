"""Orchestration: sources → detectors → dedupe → blast radius → baseline."""

from __future__ import annotations

import json
import os
import time
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from . import agentic
from .blast import enrich
from .models import Finding, Severity
from .scanner import scan_text
from .redaction import sanitize, sanitize_text
from .sources import Blob, iter_files, iter_history, iter_staged, read_blob


@dataclass
class ScanOptions:
    staged: bool = False
    history: bool = False
    max_commits: int = 1000
    jobs: int = 0  # 0 = auto
    baseline: Path | None = None
    min_severity: Severity = Severity.INFO
    exclude: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    root: str
    findings: list[Finding]
    files_scanned: int
    bytes_scanned: int
    duration_s: float
    suppressed: int = 0
    sources: list[str] = field(default_factory=list)
    network_calls: int = 0


def scan_blob(blob: Blob) -> list[Finding]:
    tags = agentic.exposure_tags(blob.location.path)
    findings = agentic.audit(blob.location.path, blob.text, blob.location)
    findings += scan_text(blob.text, blob.location)
    for f in findings:
        for t in tags:
            if t not in f.tags:
                f.tags.append(t)
    return findings


def _scan_paths(chunk: list[tuple[str, str]]) -> tuple[list[Finding], int, int]:
    out: list[Finding] = []
    files = nbytes = 0
    for abs_path, rel in chunk:
        for blob in read_blob(Path(abs_path), rel):
            files += 1
            nbytes += len(blob.text)
            out.extend(scan_blob(blob))
    return out, files, nbytes


def _chunks(items: list[tuple[str, str]], n: int) -> Iterable[list[tuple[str, str]]]:
    size = max(1, len(items) // (n * 4) or 1)
    for i in range(0, len(items), size):
        yield items[i : i + size]


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Same secret in several places → one finding per (rule, secret, path);
    the same secret recurring in history merges into the worktree finding."""
    by_fp: dict[tuple[str, str], Finding] = {}
    out: list[Finding] = []
    for f in findings:
        if not f.fingerprint:
            k = ("cfg", f.rule_id, f.location.path, f.message)
            prev = by_fp.get(k)
            if prev is None:
                by_fp[k] = f
                out.append(f)
            elif f.location.origin == "git-history" and "git-history" not in prev.tags:
                prev.tags.append("git-history")
                prev.location.commit = prev.location.commit or f.location.commit
            continue
        # an agent-config finding and a raw-secret finding for the same value
        # in the same file describe one problem: keep the richer agent one.
        k_path = ("path", f.location.path.split("!/")[0], f.fingerprint)
        k_rule = (f.rule_id, f.fingerprint)
        prev = by_fp.get(k_path) or (by_fp.get(k_rule) if f.location.origin == "git-history" else None)
        if prev is not None:
            if f.location.origin == "git-history" and "git-history" not in prev.tags:
                prev.tags.append("git-history")
                prev.location.commit = prev.location.commit or f.location.commit
            for t in f.tags:
                if t not in prev.tags:
                    prev.tags.append(t)
            if prev.provider in (None, "mcp", "generic") and f.provider not in (None, "mcp", "generic"):
                prev.provider = f.provider
            continue
        by_fp[k_path] = f
        by_fp.setdefault(k_rule, f)
        out.append(f)
    return out


def load_baseline(path: Path | None) -> set[str]:
    if not path or not path.is_file():
        return set()
    data = json.loads(path.read_text())
    entries = data.get("findings", []) if isinstance(data, dict) else data
    if not isinstance(entries, list):
        raise ValueError("Baseline must contain a findings list")
    return {e["id"] if isinstance(e, dict) else e for e in entries}


def run(target: Path, opts: ScanOptions) -> ScanResult:
    t0 = time.perf_counter()
    target = target.resolve()
    findings: list[Finding] = []
    files = nbytes = 0
    sources: list[str] = []

    if opts.staged:
        sources.append("staged")
        for blob in iter_staged(target, opts.exclude):
            files += 1
            nbytes += len(blob.text)
            findings.extend(scan_blob(blob))
    else:
        sources.append("worktree")
        base = target if target.is_dir() else target.parent
        items = [(str(p), p.relative_to(base).as_posix()) for p in iter_files(target, extra_ignore=opts.exclude)]
        jobs = opts.jobs or min(8, os.cpu_count() or 1)
        if jobs > 1 and len(items) > 200:
            with ProcessPoolExecutor(max_workers=jobs) as pool:
                for res, nf, nb in pool.map(_scan_paths, list(_chunks(items, jobs))):
                    findings.extend(res)
                    files += nf
                    nbytes += nb
        else:
            res, files, nbytes = _scan_paths(items)
            findings.extend(res)

    if opts.history:
        sources.append("git-history")
        for blob in iter_history(target, opts.max_commits):
            nbytes += len(blob.text)
            findings.extend(scan_blob(blob))

    secrets = tuple({getattr(f, "_raw") for f in findings if hasattr(f, "_raw")})
    findings = [sanitize(f, secrets) for f in enrich(dedupe(findings))]
    for f in findings:
        if hasattr(f, "_raw"):
            del f._raw  # type: ignore[attr-defined]  # raw values never leave the engine

    baseline = load_baseline(opts.baseline)
    kept = [f for f in findings if f.key not in baseline and f.severity >= opts.min_severity]
    suppressed = len(findings) - len(kept)
    kept.sort(key=lambda f: (-f.severity, -(f.blast.score if f.blast else 0), f.location.path, f.location.line))
    return ScanResult(
        root=sanitize_text(str(target), secrets),
        findings=kept,
        files_scanned=files,
        bytes_scanned=nbytes,
        duration_s=time.perf_counter() - t0,
        suppressed=suppressed,
        sources=sources,
    )
