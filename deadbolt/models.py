"""Core data structures. Nothing in here ever stores a raw secret."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import Any


class Authority(IntEnum):
    """What a leaked credential can *do*. Ordered so max() works."""

    UNKNOWN = 0
    READ = 1
    WRITE = 2
    DEPLOY = 3
    ADMIN = 4

    @property
    def label(self) -> str:
        return self.name.lower()


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @property
    def sarif_level(self) -> str:
        if self >= Severity.HIGH:
            return "error"
        if self >= Severity.MEDIUM:
            return "warning"
        return "note"

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            raise ValueError(f"unknown severity: {value!r}") from exc


def fingerprint(secret: str) -> str:
    """Stable, non-reversible identifier for a secret value."""
    return "sha256:" + hashlib.sha256(secret.encode("utf-8", "replace")).hexdigest()[:24]


def redact(secret: str) -> str:
    """Show just enough to recognise a credential, never enough to use it."""
    s = secret.strip()
    if len(s) <= 8:
        return "*" * len(s)
    head = min(4, len(s) // 4)
    return f"{s[:head]}{'*' * 8}{s[-4:]}"


@dataclass
class Location:
    path: str
    line: int = 1
    column: int = 1
    origin: str = "worktree"  # worktree | staged | git-history | docker-layer | archive
    commit: str | None = None
    layer: str | None = None

    def display(self) -> str:
        loc = f"{self.path}:{self.line}"
        if self.commit:
            loc += f" @ {self.commit[:10]}"
        if self.layer:
            loc += f" [layer {self.layer[:12]}]"
        return loc


@dataclass
class BlastRadius:
    authority: Authority
    scope: str
    exposure: list[str] = field(default_factory=list)
    score: int = 0
    rationale: list[str] = field(default_factory=list)
    llm_note: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["authority"] = self.authority.label
        return d


@dataclass
class Finding:
    rule_id: str
    title: str
    category: str  # secret | agent-config
    severity: Severity
    location: Location
    message: str
    redacted: str | None = None
    fingerprint: str | None = None
    provider: str | None = None
    blast: BlastRadius | None = None
    remediation: str | None = None
    tags: list[str] = field(default_factory=list)  # exposure context: mcp-config, ci-log, ...

    @property
    def key(self) -> str:
        """Dedup / baseline key. Independent of line number so baselines survive edits."""
        basis = self.fingerprint or f"{self.location.path}:{self.message}"
        return hashlib.sha256(f"{self.rule_id}|{basis}".encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.key,
            "rule_id": self.rule_id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity.label,
            "provider": self.provider,
            "message": self.message,
            "redacted": self.redacted,
            "fingerprint": self.fingerprint,
            "location": asdict(self.location),
            "blast_radius": self.blast.to_dict() if self.blast else None,
            "remediation": self.remediation,
            "tags": sorted(set(self.tags)),
        }
