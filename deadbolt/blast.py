"""Deterministic blast-radius triage.

Answers "what can someone *do* with this, and how far has it travelled?"
using only rule metadata, decoded token claims and where the secret was
found. Same input → same output, every time. An optional local LLM may add
narrative afterwards (see triage_llm.py) but can never lower the score.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any

from .models import Authority, BlastRadius, Finding, Severity
from .rules import RULES_BY_ID

EXPOSURE_WEIGHT = {
    "git-history": (8, "Committed to git history — deleting the file does not remove it; every clone has it"),
    "docker-layer": (8, "Baked into a container image layer — anyone who can pull the image can extract it"),
    "archive": (4, "Shipped inside a build artifact / archive"),
    "ci-log": (6, "Printed to a CI/build log — logs are widely readable and retained"),
    "ci-config": (4, "Lives in CI configuration — executes with pipeline privileges"),
    "agent-context-cache": (6, "Persisted unencrypted in an agent context cache / memory store"),
    "llm-prompt": (6, "Embedded in a prompt — sent to the model provider on every call and can be echoed back"),
    "mcp-config": (5, "Inherited by every agent session that loads this MCP config"),
    "infrastructure-as-code": (4, "Hardcoded in infrastructure-as-code / container build files"),
    "staged": (0, "Staged but not yet committed — rotate anyway if it was ever pushed elsewhere"),
}

AGENT_RULE_AUTHORITY = {
    "DB-MCP-001": (Authority.WRITE, "Standing credential available to any tool call the model makes"),
    "DB-MCP-002": (Authority.WRITE, "Credential exposed via process table"),
    "DB-MCP-003": (Authority.READ, "Model can read host secrets (SSH keys, cloud creds, browser profiles)"),
    "DB-MCP-004": (Authority.DEPLOY, "Whoever controls the package registry controls code the agent runs"),
    "DB-MCP-005": (Authority.WRITE, "Network attacker can read or tamper with tool traffic"),
    "DB-MCP-006": (Authority.ADMIN, "Side-effecting actions execute with no human checkpoint"),
    "DB-MCP-007": (Authority.ADMIN, "Prompt injection → arbitrary command execution on the host"),
    "DB-MCP-008": (Authority.ADMIN, "Container has host-level privileges"),
    "DB-AGT-001": (Authority.ADMIN, "Agent holds standing wildcard / org-wide authority"),
}


def _b64json(part: str) -> dict[str, Any] | None:
    try:
        pad = "=" * (-len(part) % 4)
        data = json.loads(base64.urlsafe_b64decode(part + pad))
        return data if isinstance(data, dict) else None
    except (ValueError, json.JSONDecodeError):
        return None


def decode_jwt_claims(token: str) -> dict[str, Any] | None:
    """Decode (NOT verify) a JWT payload. Signature verification is irrelevant here:
    we want to know what the token *claims* it can do if an attacker replays it."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    return _b64json(parts[1])


def _jwt_authority(claims: dict[str, Any]) -> tuple[Authority, list[str]]:
    notes: list[str] = []
    auth = Authority.READ
    role = str(claims.get("role", "")).lower()
    scopes = " ".join(str(claims.get(k, "")) for k in ("scope", "scp", "permissions", "roles")).lower()
    if role in ("service_role", "admin", "superuser", "owner") or "admin" in scopes:
        auth = Authority.ADMIN
        notes.append(f"claims grant elevated role ({role or 'admin scope'}) — bypasses row-level / tenant controls")
    elif any(w in scopes for w in ("write", "deploy", "delete", "publish")):
        auth = Authority.WRITE
        notes.append("claims include write-capable scopes")
    elif role:
        notes.append(f"role claim: {role}")
    if iss := claims.get("iss"):
        notes.append(f"issuer: {str(iss)[:80]}")
    exp = claims.get("exp")
    if isinstance(exp, (int, float)):
        if exp < time.time():
            notes.append("token is expired — replay risk is low unless the signing key also leaked")
        elif exp - time.time() > 365 * 86400:
            notes.append("expiry is more than a year out — effectively a standing credential")
    else:
        notes.append("no exp claim — token never expires")
    return auth, notes


def _severity_for(score: int) -> Severity:
    if score >= 80:
        return Severity.CRITICAL
    if score >= 60:
        return Severity.HIGH
    if score >= 35:
        return Severity.MEDIUM
    if score >= 15:
        return Severity.LOW
    return Severity.INFO


def assess(finding: Finding) -> BlastRadius:
    rule = RULES_BY_ID.get(finding.rule_id)
    rationale: list[str] = []
    spend = False
    expired = False

    if rule:
        authority, scope, spend = rule.authority, rule.scope, rule.spend
    elif finding.rule_id in AGENT_RULE_AUTHORITY:
        authority, scope = AGENT_RULE_AUTHORITY[finding.rule_id]
        if finding.rule_id == "DB-MCP-001" and finding.provider and finding.provider != "mcp":
            # the env var holds a recognised provider key — inherit its authority
            for r in RULES_BY_ID.values():
                if r.provider == finding.provider:
                    authority, spend = max(authority, r.authority), r.spend
                    scope = f"{scope}; {r.scope}"
                    break
    else:
        authority, scope = Authority.UNKNOWN, "Unclassified"

    raw = getattr(finding, "_raw", None)
    if raw and raw.startswith("eyJ") and raw.count(".") == 2:
        claims = decode_jwt_claims(raw)
        if claims:
            jwt_auth, notes = _jwt_authority(claims)
            authority = jwt_auth if finding.rule_id == "DB-JWT-001" else max(authority, jwt_auth)
            rationale.extend(notes)
            expired = any("expired" in n for n in notes)
    if raw and raw.startswith(("sk_test_", "rk_test_")):
        authority = Authority.READ
        rationale.append("test-mode key — no live funds or data")

    score = int(authority) * 18
    rationale.insert(0, f"authority={authority.label}: {scope}")
    if spend:
        score += 10
        rationale.append("billable — an attacker can run up charges until the key is revoked")
    exposure: list[str] = []
    for tag in dict.fromkeys([finding.location.origin, *finding.tags]):
        if tag in EXPOSURE_WEIGHT:
            w, why = EXPOSURE_WEIGHT[tag]
            exposure.append(tag)
            score += w
            if w:
                rationale.append(why)
    if expired:
        score = max(0, score - 30)
    score = min(score, 100)
    return BlastRadius(authority=authority, scope=scope, exposure=exposure, score=score, rationale=rationale)


def enrich(findings: list[Finding]) -> list[Finding]:
    for f in findings:
        f.blast = assess(f)
        scored = _severity_for(f.blast.score)
        downgraded = any(("expired" in r or "test-mode" in r) for r in f.blast.rationale)
        f.severity = scored if downgraded else max(f.severity, scored)
    return findings
