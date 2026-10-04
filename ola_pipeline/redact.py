"""Secret handling: refuse to persist probable secrets; scrub error details."""
import re
from typing import Iterable

_PATTERNS = [
    re.compile(p)
    for p in (
        r"sk-[A-Za-z0-9_\-]{20,}",
        r"AKIA[0-9A-Z]{16}",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
        r"gh[pousr]_[A-Za-z0-9]{30,}",
        r"github_pat_[A-Za-z0-9_]{30,}",
        r"xox[abprs]-[A-Za-z0-9\-]{10,}",
        r"(?i)bearer\s+[A-Za-z0-9._\-]{20,}",
    )
]


def contains_secret(text: str, known: Iterable[str] = ()) -> bool:
    if any(len(k) >= 8 and k in text for k in known):
        return True
    return any(p.search(text) for p in _PATTERNS)


def scrub(text: str, known: Iterable[str] = ()) -> str:
    for k in known:
        if len(k) >= 8:
            text = text.replace(k, "[REDACTED]")
    for p in _PATTERNS:
        text = p.sub("[REDACTED]", text)
    return text
