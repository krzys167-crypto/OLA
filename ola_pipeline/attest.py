"""Session attestation: an Ed25519 signature over what `verify.py` can recompute from disk.

The signing key lives OUTSIDE the vault (a file named by OLA_SIGNING_KEY_FILE). It is never written
into evidence, never put in an error message, and the signer refuses a key file that is readable by
group/others or that sits inside the vault root.

What the signature does and does not give you is spelled out in verify.py. Short version: with the
public key pinned out of band (`--trusted-key`), a consistent rewrite of a session directory is
detected unless the attacker also holds the private key.
"""
from __future__ import annotations

import json
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

from . import ed25519
from .errors import SigningError
from .hashing import sha256_hex
from .vault import EvidenceVault
from .verify import (ATT_SCHEMA, attestation_message, attestation_payload, ed25519_verify,
                     inspect_session)

_SEED_HEX = re.compile(r"^[0-9a-fA-F]{64}$")


def load_seed(key_file: Path, vault_root: Optional[Path] = None) -> bytes:
    """Read a 32-byte seed (64 hex chars). Error messages never contain key material."""
    path = Path(key_file)
    try:
        st = os.stat(path)
    except OSError:
        raise SigningError("signing key file is missing or unreadable") from None
    if not stat.S_ISREG(st.st_mode):
        raise SigningError("signing key path is not a regular file")
    if os.name == "posix" and st.st_mode & 0o077:
        raise SigningError("signing key file is accessible by group/others (run: chmod 600 <keyfile>)")
    if vault_root is not None:
        root = Path(vault_root).resolve()
        resolved = path.resolve()
        if resolved == root or root in resolved.parents:
            raise SigningError("signing key file must not live inside the evidence vault")
    try:
        text = path.read_text("utf-8").strip()
    except (OSError, UnicodeDecodeError):
        raise SigningError("signing key file is unreadable") from None
    if not _SEED_HEX.match(text):
        raise SigningError("signing key file must contain exactly 64 hex characters (a 32-byte seed)")
    return bytes.fromhex(text)


def _signer(seed: bytes, prefer_pure: bool) -> Tuple[bytes, Callable[[bytes], bytes], str]:
    """Prefer the audited, constant-time `cryptography` implementation; fall back to pure Python."""
    if not prefer_pure:
        try:
            from cryptography.hazmat.primitives import serialization as ser
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        except ImportError:
            pass
        else:
            key = Ed25519PrivateKey.from_private_bytes(seed)
            pub = key.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
            return pub, key.sign, "cryptography"
    return ed25519.public_key(seed), (lambda m: ed25519.sign(seed, m)), "pure-python (not constant-time)"


def sign_session(session_dir: Path, key_file: Path, *, vault_root: Optional[Path] = None,
                 prefer_pure: bool = False) -> Dict[str, Any]:
    """Write `attestation.json` (0444, write-once) next to final.json. Returns the attestation."""
    sd = Path(session_dir)
    final_path = sd / "final.json"
    if not final_path.is_file():
        raise SigningError("cannot sign a session without final.json")
    seed = load_seed(key_file, vault_root)
    try:
        pub, sign, impl = _signer(seed, prefer_pure)
    finally:
        del seed
    facts = inspect_session(sd)
    if not facts.envelopes:
        raise SigningError("cannot sign a session without envelopes")
    final_bytes = final_path.read_bytes()
    final = json.loads(final_bytes.decode("utf-8"))
    signed_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    payload = attestation_payload(sd.name, facts.envelopes[-1]["envelope_hash"], final_bytes, final,
                                  pub.hex(), signed_at)
    signature = sign(attestation_message(payload))
    # bug guard (not an authenticity claim): never write a signature the verifier would reject
    if not ed25519_verify(pub, attestation_message(payload), signature):
        raise SigningError("internal error: produced a signature that does not verify")
    att = {
        "schema": ATT_SCHEMA, "algorithm": "Ed25519", "key_id": sha256_hex(pub),
        "public_key": pub.hex(), "signer_impl": impl, "payload": payload, "signature": signature.hex(),
    }
    EvidenceVault.write_attestation_to(sd, att)
    return att


def generate_keypair(out: Path) -> Dict[str, str]:
    """Create `out` (0600, seed hex) and `out + '.pub'` (public key hex). Never overwrites."""
    out = Path(out)
    pub_path = out.with_name(out.name + ".pub")
    # Check BOTH targets before creating anything: a leftover `.pub` must not leave behind a freshly
    # created private key that has no matching public file (the user would not know which half is real).
    for target in (out, pub_path):
        if os.path.lexists(target):
            raise SigningError(f"refusing to overwrite existing file: {target}")
    seed = ed25519.generate_seed()
    pub = ed25519.public_key(seed)
    try:
        fd = os.open(str(out), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise SigningError(f"refusing to overwrite existing file: {out}") from None
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(seed.hex() + "\n")
        pub_fd = os.open(str(pub_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        with os.fdopen(pub_fd, "w", encoding="utf-8") as fh:
            fh.write(pub.hex() + "\n")
    except BaseException as exc:
        # we created `out` a moment ago (O_EXCL) — never leave a half-made key pair behind
        try:
            os.unlink(out)
        except OSError:
            pass
        if isinstance(exc, FileExistsError):
            raise SigningError(f"refusing to overwrite existing file: {pub_path}") from None
        raise
    return {"private_key_file": str(out), "public_key_file": str(pub_path),
            "public_key": pub.hex(), "key_id": sha256_hex(pub)}
