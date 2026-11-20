"""Secret detection over text blobs.

Design goals: zero dependencies, zero network, linear-time prefilter.
A rule's regex only runs if one of its lowercase keywords is present in the
blob, so most files cost a single `lower()` plus a few substring checks.
"""

from __future__ import annotations

import math
import re
from collections import Counter

from .models import Finding, Location, fingerprint, redact
from .rules import ALL_RULES, GENERIC_RULE, Rule, is_placeholder

INLINE_ALLOW = "deadbolt:allow"

_GCP_KEY_ID = re.compile(r"\"private_key_id\"\s*:\s*\"([0-9a-f]{20,64})\"")
_GCP_EMAIL = re.compile(r"\"client_email\"\s*:\s*\"([^\"]+)\"")


# Fast path for the generic rule: locate keywords with str.find (C speed), then
# run a short anchored regex only at those offsets.
_GEN_ANCHORS = ("secret", "token", "passw", "pwd", "credential", "key")
_GEN_TAIL = re.compile(
    r"[a-z0-9_.\-]{0,24}[\"']?[ \t]*(?::|=|:=|=>)[ \t]*[\"']?([A-Za-z0-9_\-+/=.~!@#$%^&*]{12,200})", re.I
)
_KEY_PREFIX = re.compile(r"(api|auth|private|access|secret|signing|encryption|master|license|client)[_\-.]?$")


def _generic_matches(text: str, lowered: str) -> list[re.Match[str]]:
    if len(lowered) != len(text):  # exotic unicode changed lengths: use the slow, exact regex
        return list(GENERIC_RULE.pattern.finditer(text))
    out: dict[int, re.Match[str]] = {}
    for anchor in _GEN_ANCHORS:
        pos = lowered.find(anchor)
        while pos != -1:
            end = pos + len(anchor)
            if anchor != "key" or _KEY_PREFIX.search(lowered, max(0, pos - 12), pos):
                m = _GEN_TAIL.match(text, end)
                if m and m.start(1) not in out:
                    out[m.start(1)] = m
            pos = lowered.find(anchor, end)
    return [out[k] for k in sorted(out)]


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _line_col(text: str, offset: int, line_starts: list[int]) -> tuple[int, int]:
    # binary search over precomputed line starts
    lo, hi = 0, len(line_starts) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if line_starts[mid] <= offset:
            lo = mid
        else:
            hi = mid - 1
    return lo + 1, offset - line_starts[lo] + 1


def _line_starts(text: str) -> list[int]:
    starts = [0]
    find = text.find
    i = find("\n")
    while i != -1:
        starts.append(i + 1)
        i = find("\n", i + 1)
    return starts


def _line_text(text: str, line_starts: list[int], line: int) -> str:
    start = line_starts[line - 1]
    end = line_starts[line] - 1 if line < len(line_starts) else len(text)
    return text[start:end]


def _extract(rule: Rule, match: re.Match[str], text: str) -> str | None:
    if rule.id == "DB-GCP-001":
        if "private_key" not in text:
            return None
        kid = _GCP_KEY_ID.search(text)
        email = _GCP_EMAIL.search(text)
        ident = (kid.group(1) if kid else "") + "|" + (email.group(1) if email else "")
        return ident if ident != "|" else match.group(0)
    if rule.id == "DB-PK-001":
        # fingerprint on the key body, not the header
        end = text.find("-----END", match.end())
        body = text[match.end() : end if end != -1 else match.end() + 4096]
        body = "".join(body.split())
        if len(body) < 64:
            return None  # header in docs / a regex, not real key material
        return body
    return match.group(rule.group)


def scan_text(text: str, location: Location, rules: tuple[Rule, ...] = ALL_RULES) -> list[Finding]:
    lowered = text.lower()
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    specific_spans: list[tuple[int, int]] = []
    line_starts: list[int] | None = None

    for rule in rules:
        if not any(k in lowered for k in rule.keywords):
            continue
        matches = _generic_matches(text, lowered) if rule is GENERIC_RULE else rule.pattern.finditer(text)
        for m in matches:
            secret = _extract(rule, m, text)
            if not secret:
                continue
            span = m.span(rule.group) if rule.group else m.span()
            if rule is GENERIC_RULE and any(s <= span[0] < e for s, e in specific_spans):
                continue  # already explained by a provider-specific rule
            if is_placeholder(secret):
                continue
            if rule.min_entropy and shannon_entropy(secret) < rule.min_entropy:
                continue
            if line_starts is None:
                line_starts = _line_starts(text)
            line, col = _line_col(text, span[0], line_starts)
            if INLINE_ALLOW in _line_text(text, line_starts, line):
                continue
            fp = fingerprint(secret)
            if (rule.id, fp) in seen:
                continue
            seen.add((rule.id, fp))
            if rule is not GENERIC_RULE:
                # a service-account file explains every value inside it
                specific_spans.append((0, len(text)) if rule.id == "DB-GCP-001" else span)
            loc = Location(
                path=location.path,
                line=location.line + line - 1,
                column=col,
                origin=location.origin,
                commit=location.commit,
                layer=location.layer,
            )
            shown = redact(secret) if rule.id not in ("DB-GCP-001",) else "service-account:" + redact(secret)
            findings.append(
                Finding(
                    rule_id=rule.id,
                    title=rule.title,
                    category="secret",
                    severity=rule.severity,
                    location=loc,
                    message=f"{rule.title} detected ({shown})",
                    redacted=shown,
                    fingerprint=fp,
                    provider=rule.provider,
                    remediation=rule.revoke[0] if rule.revoke else None,
                )
            )
            # stash the raw value transiently for claim decoding; stripped before output
            findings[-1]._raw = secret  # type: ignore[attr-defined]
    return findings
