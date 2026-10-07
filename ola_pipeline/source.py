"""Source anchor: the frozen identity of the code that produced the evidence.

Order matters: the anchor is frozen BEFORE any run_id exists and re-frozen at the
end of the run, BEFORE the final nonce is minted. A mismatch means the source
changed mid-run and the Gate blocks.
"""
import secrets
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .hashing import canonical_hash, sha256_hex


@dataclass(frozen=True)
class SourceAnchor:
    sha: str  # "" == UNKNOWN (never silently substituted)
    kind: str  # git-clean | tree-sha256 | tree-sha256(dirty-git) | UNKNOWN
    frozen_at: str
    frozen: bool = True


def _git(root: Path, *args: str) -> Optional[str]:
    try:
        r = subprocess.run(
            ["git", "-C", str(root), *args], capture_output=True, text=True, timeout=10
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout.strip() if r.returncode == 0 else None


def _tree_digest(pkg_dir: Path) -> str:
    files = sorted(p for p in pkg_dir.rglob("*.py") if "__pycache__" not in p.parts)
    if not files:
        return ""
    return canonical_hash(
        [[str(p.relative_to(pkg_dir)), sha256_hex(p.read_bytes())] for p in files]
    )


def freeze_source(pkg_dir: Optional[Path] = None) -> SourceAnchor:
    pkg = Path(pkg_dir) if pkg_dir else Path(__file__).resolve().parent
    now = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    head = _git(pkg, "rev-parse", "HEAD")
    if head:
        dirty = _git(pkg, "status", "--porcelain", "--", str(pkg))
        if dirty == "":
            return SourceAnchor(head, "git-clean", now)
        digest = _tree_digest(pkg)
        if digest:
            return SourceAnchor(digest, "tree-sha256(dirty-git)", now)
    digest = _tree_digest(pkg)
    if digest:
        return SourceAnchor(digest, "tree-sha256", now)
    return SourceAnchor("", "UNKNOWN", now)


class RunIdFactory:
    """Mints unique run ids; refuses to work without a frozen anchor."""

    def __init__(self, anchor: SourceAnchor):
        if not anchor.frozen:
            raise RuntimeError("source anchor must be frozen before minting run ids")
        self._seen = set()

    def new(self) -> str:
        while True:
            rid = "run_" + secrets.token_hex(16)
            if rid not in self._seen:
                self._seen.add(rid)
                return rid


def mint_final_nonce(end_anchor: SourceAnchor) -> str:
    """Final nonce — only after the FINAL source anchor is frozen."""
    if not end_anchor.frozen:
        raise RuntimeError("final nonce requested before final source SHA was frozen")
    return secrets.token_hex(16)
