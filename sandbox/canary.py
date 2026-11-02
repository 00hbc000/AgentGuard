"""Canary (honeypot secret) helpers shared by the sink, the in-pod harness and the host.

A canary is a fake secret that embeds the scan token, e.g.
``AGCANARY-<32 hex scan token>-AWS_SECRET_ACCESS_KEY``. If it ever shows up in
network traffic or program output it is *proof* that the skill read a honeypot
and moved the data, independent of any path heuristics.
"""
from __future__ import annotations

import base64
import binascii
import re
import urllib.parse

PATTERN = re.compile(r"AGCANARY-([0-9a-f]{32})-([A-Z0-9_]{2,40})")
_B64_CHUNK = re.compile(rb"[A-Za-z0-9+/_\-]{24,}={0,2}")
_HEX_CHUNK = re.compile(rb"(?:[0-9a-fA-F]{2}){24,}")
_MAX_SCAN_BYTES = 256 * 1024

CANARY_ENV_NAMES = (
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY", "NPM_TOKEN", "DATABASE_URL",
)


def canary_value(scan_token: str, name: str) -> str:
    return f"AGCANARY-{scan_token}-{name}"


def canary_env(scan_token: str) -> dict[str, str]:
    return {name: canary_value(scan_token, name) for name in CANARY_ENV_NAMES}


def _scan_text(text: str, encoding: str, found: dict[tuple[str, str], str]) -> None:
    for match in PATTERN.finditer(text):
        found.setdefault((match.group(1), match.group(2)), encoding)


def find_canaries(data: bytes | str) -> list[dict[str, str]]:
    """Return ``[{"token", "name", "encoding"}]`` for every canary found.

    Detects raw, URL-encoded, base64 (standard/urlsafe), and hex-encoded copies,
    including doubly-wrapped base64.
    """
    raw = data.encode("utf-8", errors="replace") if isinstance(data, str) else bytes(data)
    raw = raw[:_MAX_SCAN_BYTES]
    found: dict[tuple[str, str], str] = {}
    text = raw.decode("utf-8", errors="replace")
    _scan_text(text, "plain", found)
    unquoted = urllib.parse.unquote_plus(text)
    if unquoted != text:
        _scan_text(unquoted, "url", found)

    def decode_layers(blob: bytes, depth: int) -> None:
        if depth <= 0:
            return
        candidates = [(m.group(0), "base64") for m in _B64_CHUNK.finditer(blob)]
        candidates.extend((m.group(0), "hex") for m in _HEX_CHUNK.finditer(blob))
        stripped = blob.strip()
        if stripped:
            candidates.append((stripped, "base64"))
        for chunk, kind in candidates:
            decoded = None
            try:
                if kind == "hex":
                    decoded = binascii.unhexlify(chunk)
                else:
                    padded = chunk + b"=" * (-len(chunk) % 4)
                    decoded = base64.b64decode(padded.replace(b"-", b"+").replace(b"_", b"/"), validate=False)
            except (binascii.Error, ValueError):
                continue
            if not decoded:
                continue
            before = len(found)
            _scan_text(decoded.decode("utf-8", errors="replace"), kind, found)
            if len(found) == before:
                decode_layers(decoded, depth - 1)

    decode_layers(raw, 2)
    return [{"token": token, "name": name, "encoding": encoding}
            for (token, name), encoding in sorted(found.items())]
