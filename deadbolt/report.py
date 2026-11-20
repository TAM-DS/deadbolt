"""Text, JSON and SARIF 2.1.0 renderers. Raw secrets never reach any of them."""

from __future__ import annotations

import json
import sys
from collections import Counter
from typing import Any, TextIO

from . import __version__
from .blast import AGENT_RULE_AUTHORITY
from .engine import ScanResult
from .models import Severity
from .rules import ALL_RULES

_COLORS = {
    Severity.CRITICAL: "\033[1;97;41m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[2m",
}
_RESET, _DIM, _BOLD = "\033[0m", "\033[2m", "\033[1m"

AGENT_RULE_TITLES = {
    "DB-MCP-001": "Standing credential in MCP server config",
    "DB-MCP-002": "Credential in MCP server arguments",
    "DB-MCP-003": "MCP filesystem server rooted too broadly",
    "DB-MCP-004": "Unpinned MCP server package or image",
    "DB-MCP-005": "MCP server over plaintext HTTP",
    "DB-MCP-006": "Human approval bypassed for side-effecting tools",
    "DB-MCP-007": "Arbitrary command execution exposed to the model",
    "DB-MCP-008": "MCP container escapes its sandbox",
    "DB-AGT-001": "Over-privileged agent / tool grant",
}


def render_text(result: ScanResult, out: TextIO = sys.stdout, color: bool | None = None) -> None:
    color = out.isatty() if color is None else color

    def c(code: str, s: str) -> str:
        return f"{code}{s}{_RESET}" if color else s

    w = out.write
    w(c(_BOLD, f"DeadBolt {__version__}") + c(_DIM, f"  ·  {result.root}  ·  sources: {', '.join(result.sources)}\n"))
    w(c(_DIM, f"{result.files_scanned} files · {result.bytes_scanned / 1e6:.2f} MB · "
              f"{result.duration_s * 1000:.0f} ms · {result.network_calls} attempted network calls\n\n"))
    if not result.findings:
        w(c("\033[32m", "✔ No findings.\n"))
        return
    for f in result.findings:
        sev = c(_COLORS[f.severity], f" {f.severity.label.upper():8} ")
        w(f"{sev} {c(_BOLD, f.rule_id)}  {f.title}\n")
        w(f"           {f.location.display()}  {c(_DIM, f.location.origin)}\n")
        w(f"           {f.message}\n")
        if f.blast:
            b = f.blast
            w(c(_DIM, f"           blast radius {b.score:>3}/100 · estimated authority={b.authority.label}"
                      + (f" · exposure={','.join(b.exposure)}" if b.exposure else "") + "\n"))
            for r in b.rationale[1:4]:
                w(c(_DIM, f"             – {r}\n"))
            if b.llm_note:
                w(c(_DIM, f"             ⓘ local-LLM note: {b.llm_note}\n"))
        w("\n")
    counts = Counter(f.severity for f in result.findings)
    summary = " · ".join(f"{counts[s]} {s.label}" for s in sorted(counts, reverse=True))
    w(c(_BOLD, f"{len(result.findings)} findings: ") + summary)
    if result.suppressed:
        w(c(_DIM, f"  ({result.suppressed} suppressed by baseline/threshold)"))
    w("\n")


def to_json(result: ScanResult) -> dict[str, Any]:
    return {
        "tool": "deadbolt",
        "version": __version__,
        "root": result.root,
        "sources": result.sources,
        "stats": {
            "files_scanned": result.files_scanned,
            "bytes_scanned": result.bytes_scanned,
            "duration_ms": round(result.duration_s * 1000, 1),
            "network_calls": result.network_calls,
            "suppressed": result.suppressed,
        },
        "summary": dict(Counter(f.severity.label for f in result.findings)),
        "findings": [f.to_dict() for f in result.findings],
    }


_SEC_SEV = {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5", Severity.LOW: "3.0", Severity.INFO: "1.0"}


def to_sarif(result: ScanResult) -> dict[str, Any]:
    rules: list[dict[str, Any]] = []
    for r in ALL_RULES:
        rules.append({
            "id": r.id,
            "name": r.title.replace(" ", ""),
            "shortDescription": {"text": r.title},
            "fullDescription": {"text": f"{r.title}. Estimated potential authority if leaked: {r.authority.label} — {r.scope}"},
            "help": {"text": "Revocation runbook:\n" + "\n".join(f"- {s}" for s in r.revoke)},
            "defaultConfiguration": {"level": r.severity.sarif_level},
            "properties": {"tags": ["security", "secret", r.provider], "security-severity": _SEC_SEV[r.severity]},
        })
    for rid, title in AGENT_RULE_TITLES.items():
        auth, why = AGENT_RULE_AUTHORITY[rid]
        rules.append({
            "id": rid,
            "name": title.replace(" ", "").replace("/", ""),
            "shortDescription": {"text": title},
            "fullDescription": {"text": f"{title}. {why}"},
            "defaultConfiguration": {"level": "error"},
            "properties": {"tags": ["security", "agentic", "mcp"], "security-severity": "8.0"},
        })
    index = {r["id"]: i for i, r in enumerate(rules)}
    results = []
    for f in result.findings:
        results.append({
            "ruleId": f.rule_id,
            "ruleIndex": index[f.rule_id],
            "level": f.severity.sarif_level,
            "message": {"text": f.message + (f" | blast radius {f.blast.score}/100, estimated authority={f.blast.authority.label}"
                                             if f.blast else "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.location.path.replace("\\", "/")},
                    "region": {"startLine": max(1, f.location.line), "startColumn": max(1, f.location.column)},
                }
            }],
            "partialFingerprints": {"deadbolt/v1": f.key},
            "properties": {
                "security-severity": _SEC_SEV[f.severity],
                "origin": f.location.origin,
                "commit": f.location.commit,
                "blastRadius": f.blast.to_dict() if f.blast else None,
                "tags": sorted(set(f.tags)),
            },
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "DeadBolt",
                "version": __version__,
                "informationUri": "https://github.com/TAM-DS/deadbolt",
                "rules": rules,
            }},
            "results": results,
        }],
    }


def dump(obj: Any, out: TextIO) -> None:
    json.dump(obj, out, indent=2, sort_keys=False)
    out.write("\n")
