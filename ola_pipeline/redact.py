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
        r"(?:sk|rk|pk)_live_[A-Za-z0-9]{10,}",                    # Stripe live keys
        r"whsec_[A-Za-z0-9]{10,}",                               # Stripe webhook secret
        r"AIza[0-9A-Za-z_\-]{30,}",                              # Google API key
        r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}",   # JWT
        r"hooks\.slack\.com/services/[A-Za-z0-9/]{20,}",
        r"(?i)authorization:\s*basic\s+[A-Za-z0-9+/=]{8,}",
        r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s/:@]+:[^\s/@]+@",         # scheme://user:password@host
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
