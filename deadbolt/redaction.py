"""Redact detected credential values and URL parameters in output metadata."""
from __future__ import annotations

import re
from dataclasses import fields, is_dataclass, replace
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .models import Location, redact
from .scanner import scan_text

_URL = re.compile(r"https?://[^\s<>\"'`]+", re.I)


def _safe_url(match: re.Match[str]) -> str:
    try:
        url = urlsplit(match.group())
        host = url.netloc.rsplit("@", 1)[-1]
        if "@" in url.netloc:
            host = "[REDACTED]@" + host
        # Query strings and fragments may carry opaque credentials of any format.
        return urlunsplit((url.scheme, host, url.path,
                           "[REDACTED]" if url.query else "",
                           "[REDACTED]" if url.fragment else ""))
    except ValueError:
        return "[REDACTED URL]"


def sanitize_text(text: str, secrets: tuple[str, ...] = ()) -> str:
    detected = [getattr(f, "_raw", "") for f in scan_text(text.replace("deadbolt:allow", ""), Location("metadata"))]
    for secret in sorted(set(secrets) | set(detected), key=len, reverse=True):
        if secret:
            text = text.replace(secret, redact(secret))
    text = _URL.sub(_safe_url, text)
    # Prevent untrusted metadata or model output from emitting terminal controls.
    return "".join(c if c >= " " or c in "\n\t" else "?" for c in text)


def sanitize(value: Any, secrets: tuple[str, ...] = ()) -> Any:
    if isinstance(value, str):
        return sanitize_text(value, secrets)
    if is_dataclass(value):
        return replace(value, **{f.name: sanitize(getattr(value, f.name), secrets) for f in fields(value)})
    if isinstance(value, list):
        return [sanitize(v, secrets) for v in value]
    if isinstance(value, dict):
        return {sanitize(k, secrets): sanitize(v, secrets) for k, v in value.items()}
    return value
