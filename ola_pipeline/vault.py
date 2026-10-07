"""Append-only evidence vault (filesystem).

* every file is created with O_EXCL and mode 0444 -> existing evidence is never overwritten
* envelopes form a SHA-256 hash chain (prev_envelope_hash)
* artifacts are content-addressed (file name == SHA-256 of content)
* run ids and bindings are registered globally -> reuse raises ReplayDetected

This is integrity, not authenticity: see verify.py docstring.
"""
from __future__ import annotations

import json
import os
import re
import threading
from pathlib import Path
from typing import Any, Dict

from .errors import ReplayDetected, VaultError
from .hashing import sha256_hex
from .verify import GENESIS, compute_binding, compute_envelope_hash

_SAFE_ID = re.compile(r"^[A-Za-z0-9_\-]{1,80}$")


def _write_new(path: Path, data: bytes) -> None:
    try:
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
    except FileExistsError:
        raise ReplayDetected(f"refusing to overwrite existing evidence: {path.name}") from None
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
    except BaseException:
        raise


class EvidenceVault:
    def __init__(self, root: Path, session_id: str):
        if not _SAFE_ID.match(session_id):
            raise VaultError("unsafe session id")
        self.root = Path(root)
        self.session_id = session_id
        self.dir = self.root / session_id
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            self.dir.mkdir()
        except FileExistsError:
            raise ReplayDetected("session directory already exists") from None
        (self.dir / "envelopes").mkdir()
        (self.dir / "artifacts").mkdir()
        (self.root / "_run_index").mkdir(exist_ok=True)
        (self.root / "_binding_index").mkdir(exist_ok=True)
        self._lock = threading.Lock()
        self._seq = 0
        self._prev = GENESIS

    # ----------------------------------------------------------------- artifacts
    def put_artifact(self, data: bytes) -> str:
        h = sha256_hex(data)
        p = self.dir / "artifacts" / h
        if p.exists():
            if sha256_hex(p.read_bytes()) != h:
                raise VaultError("existing artifact does not match its hash")
            return h
        _write_new(p, data)
        return h

    def get_artifact(self, h: str) -> bytes:
        if not re.fullmatch(r"[0-9a-f]{64}", h or ""):
            raise VaultError("malformed artifact hash")
        p = self.dir / "artifacts" / h
        if not p.is_file():
            raise VaultError("artifact missing")
        data = p.read_bytes()
        if sha256_hex(data) != h:
            raise VaultError("artifact content does not match its hash")
        return data

    # ----------------------------------------------------------------- envelopes
    def append_envelope(self, env: Dict[str, Any]) -> Dict[str, Any]:
        run_id = env.get("run_id", "")
        if not _SAFE_ID.match(str(run_id)):
            raise VaultError("unsafe run_id")
        with self._lock:
            _write_new(self.root / "_run_index" / run_id, self.session_id.encode())
            e = dict(env)
            e["seq"] = self._seq + 1
            e["prev_envelope_hash"] = self._prev
            e["binding"] = compute_binding(e)
            _write_new(self.root / "_binding_index" / e["binding"], run_id.encode())
            e["envelope_hash"] = compute_envelope_hash(e)
            name = f"{e['seq']:04d}_{run_id}.json"
            _write_new(
                self.dir / "envelopes" / name,
                json.dumps(e, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8"),
            )
            self._seq = e["seq"]
            self._prev = e["envelope_hash"]
            return e

    @staticmethod
    def write_attestation_to(session_dir: Path, attestation: Dict[str, Any]) -> Path:
        """attestation.json is write-once and read-only, like every other piece of evidence."""
        p = Path(session_dir) / "attestation.json"
        _write_new(p, json.dumps(attestation, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8"))
        return p

    def write_final(self, final: Dict[str, Any]) -> Path:
        p = self.dir / "final.json"
        _write_new(p, json.dumps(final, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8"))
        return p
