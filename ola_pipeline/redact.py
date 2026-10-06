"""Secret handling: refuse to persist probable secrets; scrub error details.

Fail closed: when in doubt a string is treated as a secret. Two things keep that from blocking ordinary prose:
  * token-style patterns (sk-..., sk_live_..., JWT) must start at a word boundary, so "risk-based-approach-..."
    or "task-management-..." is not an `sk-` key. The boundary also holds right after an escaped newline/tab
    (backslash + n/r/t) or a %XX escape, where the preceding letter belongs to the escape and not to a word,
    so a real key in "...\\nsk-abc..." or "key%3Dsk-abc..." is still found;
  * a DSN password that is, as a WHOLE, an obvious placeholder (password, <password>, ${DB_PASSWORD}, ****)
    is not a secret. Only the entire password field is matched, so a real secret cannot hide behind it.
Every pattern is linear on adversarial input (long alphanumeric runs, repeated prefixes): each can only start
at a boundary, or consumes its own match, so 200k characters scan in a few milliseconds.
"""
import re
from typing import Iterable

# word boundary in front of a token whose own characters are [A-Za-z0-9] (+ "_" and "-" for the wide variant)
_LB = r"(?:(?<![A-Za-z0-9])|(?<=\\[nrt])|(?<=%[0-9A-Fa-f]{2}))"
_LB_WIDE = r"(?:(?<![A-Za-z0-9_\-])|(?<=\\[nrt])|(?<=%[0-9A-Fa-f]{2}))"
# a DSN password that is nothing but a placeholder; bounded and without "/" so scanning stays local
_PLACEHOLDER = (r"(?i:password|passwd|pass|pwd|secret|your[_-]?password|x{3,}|\*+"
                r"|<[^>@\s/]{0,64}>|\$\{[^}@\s/]{0,64}\}|\{\{[^}@\s/]{0,64}\}\})")

_PATTERNS = [
    re.compile(p)
    for p in (
        _LB + r"sk-[A-Za-z0-9_\-]{20,}",
        r"AKIA[0-9A-Z]{16}",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
        r"gh[pousr]_[A-Za-z0-9]{30,}",
        r"github_pat_[A-Za-z0-9_]{30,}",
        r"xox[abprs]-[A-Za-z0-9\-]{10,}",
        r"(?i)bearer\s+[A-Za-z0-9._\-]{20,}",
        _LB + r"(?:sk|rk|pk)_live_[A-Za-z0-9]{10,}",              # Stripe live keys
        r"whsec_[A-Za-z0-9]{10,}",                               # Stripe webhook secret
        r"AIza[0-9A-Za-z_\-]{30,}",                              # Google API key
        _LB_WIDE + r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}",   # JWT
        r"hooks\.slack\.com/services/[A-Za-z0-9/]{20,}",
        r"(?i)authorization:\s*basic\s+[A-Za-z0-9+/=]{8,}",
        # scheme://user:password@host; the scheme starts where its run of scheme characters starts (linear scan),
        # a leading non-letter prefix is allowed so that "1+postgres://u:p@h" is still found
        r"(?<![A-Za-z0-9+.\-])[0-9+.\-]*[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s/:@]+:(?!" + _PLACEHOLDER + r"@)[^\s/@]+@",
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
