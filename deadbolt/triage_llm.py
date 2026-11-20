"""Optional narrative triage with a *local* model (Ollama-compatible API).

Guarantees:
  * loopback only — any non-local host is refused before a socket opens
  * the model never sees a secret: only rule id, provider, redacted form,
    path and the deterministic blast-radius rationale are sent
  * the model can add a note; it cannot change authority, score or severity
"""

from __future__ import annotations

import ipaddress
import json
import socket
import urllib.request
from urllib.parse import urlparse

from .models import Finding

DEFAULT_HOST = "http://127.0.0.1:11434"


def _is_loopback(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    return bool(infos) and all(ipaddress.ip_address(i[4][0]).is_loopback for i in infos)


def annotate(findings: list[Finding], model: str = "llama3.1:8b", host: str = DEFAULT_HOST,
             limit: int = 20, timeout: float = 30.0) -> int:
    parsed = urlparse(host)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or not _is_loopback(parsed.hostname):
        raise PermissionError(f"refusing LLM triage against non-loopback host {host!r}: DeadBolt stays offline")
    url = f"{parsed.scheme}://{parsed.netloc}/api/generate"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # never route via a proxy
    done = 0
    for f in findings[:limit]:
        if not f.blast:
            continue
        facts = {
            "rule": f.rule_id, "title": f.title, "provider": f.provider, "where": f.location.display(),
            "origin": f.location.origin, "credential_redacted": f.redacted,
            "authority": f.blast.authority.label, "score": f.blast.score, "rationale": f.blast.rationale,
        }
        prompt = (
            "You are a security triage assistant. Using ONLY the facts below, write at most two sentences "
            "explaining the realistic attacker impact and the single most urgent action. Do not invent "
            "facts, do not ask for the secret.\n\nFACTS:\n" + json.dumps(facts, indent=1)
        )
        req = urllib.request.Request(
            url, data=json.dumps({"model": model, "prompt": prompt, "stream": False}).encode(),
            headers={"Content-Type": "application/json"}, method="POST",
        )
        try:
            with opener.open(req, timeout=timeout) as resp:  # loopback enforced above
                text = json.loads(resp.read()).get("response", "").strip()
        except (OSError, ValueError):
            break
        if text:
            f.blast.llm_note = " ".join(text.split())[:400]
            done += 1
    return done
