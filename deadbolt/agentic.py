"""Agentic configuration auditor.

Classic secret scanners look for keys. Agent stacks leak *authority* in new
places: MCP server configs, agent tool manifests, prompt files, and
unencrypted context caches. This module audits those surfaces.

Supported MCP config shapes:
  * Claude Desktop / Claude Code / Cursor / Windsurf / Cline:  {"mcpServers": {...}}
  * VS Code:                                                  {"servers": {...}}
  * Codex-style TOML:                                         [mcp_servers.<name>]
"""

from __future__ import annotations

import json
import re
from pathlib import PurePosixPath
from typing import Any, Iterator

from .models import Finding, Location, Severity, fingerprint, redact
from .rules import is_placeholder
from .scanner import scan_text, shannon_entropy

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]


# --------------------------------------------------------------- exposure tags
_CACHE_PATH = re.compile(
    r"(?i)(^|/)(\.?(agent|llm|langchain|langgraph|crewai|autogen|memory|context|conversation|chat)"
    r"[_\-]?(cache|memory|history|store|state|checkpoints?)|\.mem0|checkpoints)(/|$)"
)
_CACHE_FILE = re.compile(r"(?i)(history|memory|transcript|session|checkpoint)[^/]*\.(json|jsonl|ndjson|txt|md)$")
_PROMPT_PATH = re.compile(
    r"(?i)((^|/)prompts?/|\.prompt(\.md|\.txt|\.ya?ml)?$|(^|/)(claude|agents|gemini)\.md$|(^|/)\.cursorrules$|system[_\-]?prompt)"
)
_CI_LOG = re.compile(r"(?i)(\.log$|(^|/)(ci[_\-]?logs?|build[_\-]?logs?|logs)/)")
_CI_CONFIG = re.compile(r"(?i)((^|/)\.github/workflows/|\.gitlab-ci\.ya?ml$|(^|/)jenkinsfile$|(^|/)\.circleci/)")
_IAC = re.compile(r"(?i)\.(tf|tfvars|tfstate)$|(^|/)(dockerfile|docker-compose\.ya?ml)$")


def exposure_tags(path: str) -> list[str]:
    tags: list[str] = []
    if _CACHE_PATH.search(path) or _CACHE_FILE.search(path):
        tags.append("agent-context-cache")
    if _PROMPT_PATH.search(path):
        tags.append("llm-prompt")
    if _CI_LOG.search(path):
        tags.append("ci-log")
    if _CI_CONFIG.search(path):
        tags.append("ci-config")
    if _IAC.search(path):
        tags.append("infrastructure-as-code")
    if is_mcp_path(path):
        tags.append("mcp-config")
    return tags


# ------------------------------------------------------------- MCP discovery
_MCP_NAMES = {
    "claude_desktop_config.json",
    "mcp.json",
    ".mcp.json",
    "mcp_config.json",
    "mcp_settings.json",
    "cline_mcp_settings.json",
}


def is_mcp_path(path: str) -> bool:
    name = PurePosixPath(path).name.lower()
    return name in _MCP_NAMES or name.endswith(".mcp.json")


def _servers_from_json(doc: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(doc, dict):
        return {}
    for key in ("mcpServers", "mcp_servers", "servers"):
        block = doc.get(key)
        if isinstance(block, dict) and block and all(isinstance(v, dict) for v in block.values()):
            if key != "servers" or any(("command" in v or "url" in v) for v in block.values()):
                return block
    # nested e.g. {"mcp": {"servers": {...}}}
    mcp = doc.get("mcp")
    if isinstance(mcp, dict):
        return _servers_from_json(mcp)
    return {}


def load_mcp_servers(path: str, text: str) -> dict[str, dict[str, Any]]:
    low = path.lower()
    if low.endswith(".json"):
        if "mcpservers" not in text.lower() and "servers" not in text and "mcp_servers" not in text:
            return {}
        try:
            return _servers_from_json(json.loads(text))
        except (json.JSONDecodeError, ValueError):
            return {}
    if low.endswith(".toml") and tomllib and "mcp_servers" in text:
        try:
            return _servers_from_json(tomllib.loads(text))
        except (tomllib.TOMLDecodeError, ValueError):
            return {}
    return {}


# ------------------------------------------------------------------- helpers
_SECRETISH_KEY = re.compile(r"(?i)(key|secret|token|passw|pwd|credential|auth|bearer|cookie|session)")
_CRED_FLAG = re.compile(r"(?i)^--?(api[_\-]?key|token|access[_\-]?token|secret|password|passwd|auth|bearer|pat)(=(.+))?$")
_BROAD_PATHS = {"/", "~", "~/", "$HOME", "${HOME}", "/home", "/Users", "/root", "C:\\", "C:/", "C:\\Users", "%USERPROFILE%"}
_EXEC_HINTS = re.compile(
    r"(?i)(server-shell|shell[_\-]?server|mcp[_\-]?shell|desktop[_\-]?commander|terminal|run[_\-]?command|code[_\-]?runner|exec)"
)
_PIN = re.compile(r"@\d+(\.\d+){0,2}([\-+][\w.]+)?$|==\d|@sha256:|:[\w.\-]+@sha256:")
_DANGEROUS_TOOL = re.compile(r"(?i)(write|delete|remove|exec|run|shell|command|push|deploy|create|update|send|transfer|kill)")


def _line_of(text: str, needle: str, anchor: str = "", default: int = 1) -> int:
    """Line of `needle`, searching from `anchor` (the server's name) onwards;
    prefers a JSON-quoted match so '/' doesn't hit the first slash in the file."""
    start = max(0, text.find(anchor)) if anchor else 0
    for cand in (json.dumps(needle), needle):
        if cand and (idx := text.find(cand, start)) >= 0:
            return text.count("\n", 0, idx) + 1
    if anchor and (idx := text.find(anchor)) >= 0:
        return text.count("\n", 0, idx) + 1
    return default


def _looks_like_secret(key: str, value: str) -> bool:
    if not isinstance(value, str) or len(value) < 8 or is_placeholder(value):
        return False
    if value.startswith(("http://", "https://", "/", "./", "~")) and "@" not in value:
        return False
    if _SECRETISH_KEY.search(key) and shannon_entropy(value) >= 3.0:
        return True
    return False


_VALUE_FLAGS = {"-v", "--volume", "-e", "--env", "--env-file", "--network", "--net", "--name", "-p", "--publish",
                "--mount", "-w", "--workdir", "-u", "--user", "--entrypoint", "--label", "-l", "--platform",
                "--cap-add", "--cap-drop", "--add-host", "--pid", "--ipc", "--memory", "-m", "--cpus"}


def _container_image(args: list[str]) -> str | None:
    if "run" not in args:
        return None
    it = iter(args[args.index("run") + 1:])
    for a in it:
        if a in _VALUE_FLAGS:
            next(it, None)
        elif not a.startswith("-"):
            return a
    return None


def _pkg_arg(args: list[str]) -> str | None:
    for a in args:
        if not a.startswith("-"):
            return a
    return None


# --------------------------------------------------------------------- audit
def audit_mcp(path: str, text: str, base: Location) -> list[Finding]:
    servers = load_mcp_servers(path, text)
    out: list[Finding] = []

    def emit(rule_id: str, title: str, sev: Severity, name: str, msg: str, fix: str,
             needle: str = "", secret: str | None = None, extra_tags: tuple[str, ...] = ()) -> Finding:
        f = Finding(
            rule_id=rule_id,
            title=title,
            category="agent-config",
            severity=sev,
            location=Location(path=path, line=_line_of(text, needle, anchor=json.dumps(name)), origin=base.origin,
                              commit=base.commit, layer=base.layer),
            message=f"[{name}] {msg}",
            redacted=redact(secret) if secret else None,
            fingerprint=fingerprint(secret) if secret else None,
            provider="mcp",
            remediation=fix,
            tags=["mcp-config", *extra_tags],
        )
        if secret:
            f._raw = secret  # type: ignore[attr-defined]
        out.append(f)
        return f

    for name, spec in servers.items():
        if not isinstance(spec, dict):
            continue
        command = str(spec.get("command", ""))
        args = [str(a) for a in spec.get("args", []) if isinstance(a, (str, int, float))]
        env = spec.get("env") or {}
        headers = spec.get("headers") or {}
        url = str(spec.get("url", "") or spec.get("serverUrl", ""))
        joined = " ".join([command, *args])

        # MCP-001: standing credentials in env / headers
        for block_name, block in (("env", env), ("headers", headers)):
            if not isinstance(block, dict):
                continue
            for k, v in block.items():
                if not isinstance(v, str):
                    continue
                value = v.split(" ", 1)[1] if v.lower().startswith("bearer ") else v
                provider_hits = scan_text(value, Location(path=path))
                if provider_hits or _looks_like_secret(k, value):
                    hit = provider_hits[0] if provider_hits else None
                    what = hit.title if hit else "credential"
                    f = emit(
                        "DB-MCP-001", "Standing credential in MCP server config", Severity.HIGH, name,
                        f"{block_name}.{k} holds a literal {what} — every agent session inherits it",
                        "Reference the secret instead of embedding it (OS keychain, 1Password/Vault ref, "
                        "${env:VAR} input prompt) and issue a short-lived, least-privilege token per session",
                        needle=v, secret=value,
                    )
                    if hit:
                        f.provider = hit.provider
                        f.severity = max(f.severity, hit.severity)

        # MCP-002: credentials passed on the command line
        for i, a in enumerate(args):
            m = _CRED_FLAG.match(a)
            val = None
            if m:
                val = m.group(3) or (args[i + 1] if i + 1 < len(args) else None)
            elif scan_text(a, Location(path=path)):
                val = a
            if val and not is_placeholder(val) and len(val) >= 8:
                emit(
                    "DB-MCP-002", "Credential in MCP server arguments", Severity.HIGH, name,
                    "credential passed as a CLI argument — visible in `ps`, shell history and crash dumps",
                    "Pass secrets through env references or a credential helper, never argv",
                    needle=val, secret=val,
                )

        # MCP-003: filesystem over-reach
        if "filesystem" in joined.lower() or "fs" in name.lower():
            broad = [a for a in args if a.rstrip("/\\") in {p.rstrip("/\\") for p in _BROAD_PATHS} or a in _BROAD_PATHS]
            if broad:
                emit(
                    "DB-MCP-003", "MCP filesystem server rooted too broadly", Severity.HIGH, name,
                    f"filesystem access granted at {broad[0]!r} — the model can read ~/.ssh, ~/.aws, browser profiles",
                    "Scope to the single project directory the agent needs; mount read-only where possible",
                    needle=broad[0],
                )

        # MCP-004: unpinned supply chain
        launcher = PurePosixPath(command).name.lower()
        if launcher in {"npx", "bunx", "pnpx", "uvx", "pipx"} or (launcher in {"pnpm", "yarn"} and "dlx" in args):
            pkg = _pkg_arg([a for a in args if a not in ("dlx", "run")])
            if pkg and (pkg.endswith("@latest") or not _PIN.search(pkg)):
                emit(
                    "DB-MCP-004", "Unpinned MCP server package", Severity.MEDIUM, name,
                    f"`{launcher} {pkg}` resolves whatever is newest at launch — a hijacked publish runs with the agent's authority",
                    "Pin an exact version (pkg@1.2.3) or vendor the server; verify provenance/signatures",
                    needle=pkg,
                )
        if launcher in {"docker", "podman"}:
            image = _container_image(args)
            if image and ("@sha256:" not in image):
                emit(
                    "DB-MCP-004", "Unpinned MCP server image", Severity.MEDIUM, name,
                    f"container image {image!r} is not digest-pinned",
                    "Pin by digest: image@sha256:<digest>",
                    needle=image,
                )
            danger = [a for a in args if a in ("--privileged", "--net=host", "--network=host", "--pid=host")
                      or "docker.sock" in a or re.match(r"^/:/", a) or a.startswith("--cap-add")]
            if "--network" in args and args[args.index("--network") + 1:args.index("--network") + 2] == ["host"]:
                danger.append("--network host")
            if danger:
                emit(
                    "DB-MCP-008", "MCP container escapes its sandbox", Severity.HIGH, name,
                    f"container launched with {', '.join(danger)} — host-level authority for the agent",
                    "Drop privileged flags and host mounts; run rootless with a read-only filesystem",
                    needle=danger[0].split()[0],
                )

        # MCP-005: insecure remote transport
        if url.startswith("http://") and not re.match(r"http://(localhost|127\.0\.0\.1|\[::1\])(:|/|$)", url):
            emit(
                "DB-MCP-005", "MCP server over plaintext HTTP", Severity.HIGH, name,
                f"remote MCP endpoint {url} is not TLS — tool calls and tokens cross the network in clear text",
                "Use https:// with OAuth 2.1 / short-lived tokens",
                needle=url,
            )

        # MCP-006 / MCP-007: auto-approval and command execution
        auto = spec.get("autoApprove", spec.get("alwaysAllow", spec.get("auto_approve")))
        trust = spec.get("trust") is True
        exec_like = bool(_EXEC_HINTS.search(joined) or _EXEC_HINTS.search(name))
        auto_all = auto == "*" or auto is True or trust or (isinstance(auto, list) and "*" in auto)
        risky_auto = [t for t in auto if isinstance(t, str) and _DANGEROUS_TOOL.search(t)] if isinstance(auto, list) else []
        if auto_all or risky_auto:
            sev = Severity.CRITICAL if exec_like else Severity.HIGH
            what = "every tool" if auto_all else ", ".join(risky_auto[:4])
            emit(
                "DB-MCP-006", "Human approval bypassed for side-effecting tools", sev, name,
                f"auto-approve covers {what} — the model acts without a human in the loop",
                "Auto-approve read-only tools only; require explicit approval for write/exec/network tools",
                needle="autoApprove" if "autoApprove" in spec else ("alwaysAllow" if "alwaysAllow" in spec else "trust"),
            )
        if exec_like:
            emit(
                "DB-MCP-007", "Arbitrary command execution exposed to the model", Severity.HIGH if not auto_all else Severity.CRITICAL,
                name,
                "server exposes shell/command execution — prompt injection becomes remote code execution",
                "Run inside a disposable sandbox (container/VM) with no credentials mounted; allow-list commands",
            )
    return out


# ------------------------------------------------------- agent tool manifests
_WILDCARD_SCOPE = re.compile(
    r"(?im)^\s*[\"']?(scopes?|permissions?|allowed[_\-]?tools|capabilities|roles?)[\"']?\s*[:=]\s*\[?\s*[\"']?(\*|admin|all|root|full[_\-]?access|owner)[\"']?"
)
_OAUTH_BROAD = re.compile(
    r"(?i)[\"'](repo|admin:org|delete_repo|write:packages|https://www\.googleapis\.com/auth/cloud-platform|"
    r"https://mail\.google\.com/|https://www\.googleapis\.com/auth/drive|offline_access|\.default)[\"']"
)


def _iter_agent_manifest(path: str, text: str) -> Iterator[tuple[int, str, str]]:
    name = PurePosixPath(path).name.lower()
    agentish = any(t in name for t in ("agent", "tool", "crew", "assistant", "mcp", "manifest", "skill", "plugin"))
    if not agentish or not name.endswith((".json", ".yaml", ".yml", ".toml")):
        return
    for m in _WILDCARD_SCOPE.finditer(text):
        yield text.count("\n", 0, m.start()) + 1, m.group(1), m.group(2)
    for m in _OAUTH_BROAD.finditer(text):
        yield text.count("\n", 0, m.start()) + 1, "oauth-scope", m.group(1)


def audit_agent_manifest(path: str, text: str, base: Location) -> list[Finding]:
    out = []
    for line, field_name, value in _iter_agent_manifest(path, text):
        out.append(
            Finding(
                rule_id="DB-AGT-001",
                title="Over-privileged agent / tool grant",
                category="agent-config",
                severity=Severity.HIGH if value in ("*", "admin", "root", "owner", "all") else Severity.MEDIUM,
                location=Location(path=path, line=line, origin=base.origin, commit=base.commit, layer=base.layer),
                message=f"{field_name} grants {value!r} to an agent — standing authority far beyond any single task",
                provider="agent",
                remediation="Grant per-task, least-privilege scopes with expiry; broker elevation through human approval",
                tags=["agent-manifest"],
            )
        )
    return out


def audit(path: str, text: str, base: Location) -> list[Finding]:
    findings = audit_mcp(path, text, base) if (
        is_mcp_path(path) or path.lower().endswith((".json", ".toml"))
    ) else []
    findings += audit_agent_manifest(path, text, base)
    return findings
