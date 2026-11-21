"""Banner."""
from __future__ import annotations

_LOGO = [
    "█▀▀ █▄█ █▀▀   █▀▀ █  █ █▀▀ █▀▀ █ ██ █▀▀ █▀▄",
    "█   █ █ ▀▀█   █   █▀▀█ █▀▀ █   █▀▄  █▀▀ █▀▄",
    "▀▀▀ █ █ ▀▀▀   ▀▀▀ █  █ ▀▀▀ ▀▀▀ █ ▀▀ ▀▀▀ █ █",
]

_TAGLINE = [
    "> CMS & WAF Fingerprinting Engine",
    "> fast · accurate · stealth",
]


def get_banner(version: str) -> str:
    
    rows = _LOGO + [""] + _TAGLINE
    inner = max(len(r) for r in rows) + 4
    top = "╔" + "═" * inner + "╗"
    bottom = "╚" + "═" * inner + "╝"
    body = ["║  " + row.ljust(inner - 2) + "║" for row in rows]
    return "\n".join([top, "║" + " " * inner + "║"] + body + ["║" + " " * inner + "║", bottom])
