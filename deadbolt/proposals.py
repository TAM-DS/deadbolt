"""Human-approved revocation proposals.

DeadBolt never rotates, revokes or rewrites anything. It writes a *proposal*:
a deterministic, content-addressed runbook. A human approves or rejects it
into an append-only, hash-chained ledger. Any edit to a proposal after it was
generated changes its hash, so a tampered proposal cannot be approved.
"""

from __future__ import annotations

import getpass
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import Finding
from .rules import RULES_BY_ID

GENESIS = "0" * 64

AGENT_STEPS = {
    "DB-MCP-001": ["Rotate the embedded credential at its provider",
                   "Replace the literal with a secret reference / runtime prompt",
                   "Issue a per-session, least-privilege token instead of a standing key"],
    "DB-MCP-002": ["Rotate the credential", "Move it from argv to an env reference or credential helper"],
    "DB-MCP-003": ["Re-scope the filesystem server to the project directory only"],
    "DB-MCP-004": ["Pin the server package/image to an exact version or digest", "Verify publisher provenance"],
    "DB-MCP-005": ["Move the endpoint to https://", "Rotate any token that crossed the plaintext link"],
    "DB-MCP-006": ["Remove auto-approval for side-effecting tools", "Keep auto-approve for read-only tools only"],
    "DB-MCP-007": ["Run the exec server inside a disposable sandbox with no mounted credentials",
                   "Allow-list commands; require human approval per call"],
    "DB-MCP-008": ["Drop --privileged / host mounts / host networking", "Run rootless with a read-only root filesystem"],
    "DB-AGT-001": ["Replace wildcard grants with task-scoped permissions that expire",
                   "Route elevation through a human approval gate"],
}


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def build_proposal(f: Finding) -> dict[str, Any]:
    rule = RULES_BY_ID.get(f.rule_id)
    steps = list(rule.revoke) if rule else list(AGENT_STEPS.get(f.rule_id, ["Investigate and remediate manually"]))
    if f.fingerprint:
        steps.append("Remove the value from the file; if it reached git history, rotating is mandatory — "
                     "history rewriting alone is not remediation")
        steps.append(f"Add {f.key} to the DeadBolt baseline only after rotation is confirmed")
    body = {
        "finding_id": f.key,
        "rule_id": f.rule_id,
        "title": f.title,
        "provider": f.provider,
        "location": f.location.display(),
        "credential": f.redacted,
        "fingerprint": f.fingerprint,
        "authority": f.blast.authority.label if f.blast else "unknown",
        "blast_score": f.blast.score if f.blast else 0,
        "severity": f.severity.label,
        "steps": steps,
        "executes_automatically": False,
    }
    return {"proposal_id": sha256(canonical(body)), "status": "pending-human-approval", **body}


def build_all(findings: list[Finding]) -> list[dict[str, Any]]:
    return [build_proposal(f) for f in findings]


def verify_proposal(p: dict[str, Any]) -> bool:
    body = {k: v for k, v in p.items() if k not in ("proposal_id", "status")}
    return sha256(canonical(body)) == p.get("proposal_id")


# ------------------------------------------------------------------ ledger
def _read_ledger(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(ln) for ln in path.read_text().splitlines() if ln.strip()]


def verify_ledger(path: Path) -> tuple[bool, str]:
    prev = GENESIS
    for i, entry in enumerate(_read_ledger(path), 1):
        claimed = entry.get("entry_hash")
        body = {k: v for k, v in entry.items() if k != "entry_hash"}
        if body.get("prev_hash") != prev:
            return False, f"entry {i}: chain broken (prev_hash mismatch)"
        if sha256(canonical(body)) != claimed:
            return False, f"entry {i}: content modified after it was written"
        prev = claimed
    return True, f"ledger intact ({len(_read_ledger(path))} entries)"


def record_decision(proposals_file: Path, ledger: Path, proposal_id: str, decision: str,
                    approver: str | None = None, reason: str = "") -> dict[str, Any]:
    if decision not in ("approve", "reject"):
        raise ValueError("decision must be approve or reject")
    proposals = json.loads(proposals_file.read_text())
    proposals = proposals.get("proposals", proposals)
    matches = [p for p in proposals if p["proposal_id"].startswith(proposal_id)]
    if len(matches) != 1:
        raise LookupError(f"{len(matches)} proposals match {proposal_id!r} — use a longer prefix")
    p = matches[0]
    if not verify_proposal(p):
        raise PermissionError("proposal content does not match its hash — it was edited after generation; refusing")
    ok, why = verify_ledger(ledger)
    if not ok:
        raise PermissionError(f"ledger failed verification: {why}")
    entries = _read_ledger(ledger)
    body = {
        "proposal_id": p["proposal_id"],
        "finding_id": p["finding_id"],
        "decision": decision,
        "approver": approver or getpass.getuser(),
        "reason": reason,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "prev_hash": entries[-1]["entry_hash"] if entries else GENESIS,
    }
    entry = {**body, "entry_hash": sha256(canonical(body))}
    ledger.parent.mkdir(parents=True, exist_ok=True)
    with ledger.open("a") as fh:
        fh.write(json.dumps(entry, sort_keys=True) + "\n")
    return entry
