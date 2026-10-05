"""External anchor: an RFC 3161 time-stamp over the tip of a tenant's evidence chain.

Why: the tenant chain and the pipeline vault live on the same host. Whoever can rewrite both (and recompute
the hashes) is not detected by anything inside the system. A time-stamp token signed by an independent
Time-Stamping Authority (TSA) proves that a given chain tip existed no later than the TSA's signing time;
rewriting history afterwards cannot reproduce a token for the old tip.

What is stamped: SHA-256 of canonical_json({"schema", "tenant_id", "tip_seq", "tip_hash"}). Only a digest
leaves the host - no payloads, no task text.

Flow
    timestamp_tip(tenant)   verify the chain -> build a DER TimeStampReq -> POST to OLA_TSA_URL
                            -> verify the reply with `openssl ts -verify` against OLA_TSA_CA_FILE
                            -> store .tsq/.tsr under OLA_ANCHOR_DIR -> append `anchor.timestamp`
    verify_timestamp(...)   re-derives everything from the chain + stored files; trusts no stored verdict.

Configuration (all required for the feature; a half-configured setup is an error, never "off")
    OLA_TSA_URL       https URL of the TSA (plain http only for loopback, used by tests)
    OLA_TSA_CA_FILE   PEM with the TSA's trust anchor(s) that YOU chose to trust
    OLA_ANCHOR_DIR    where the .tsq/.tsr files are kept (default ./ola_anchor)
    OLA_TSA_TIMEOUT_S request timeout, default 20

HONEST LIMITS
* Verified here against a LOCAL TSA built with `openssl ts` (protocol + verification logic). Compatibility
  with any commercial TSA is UNKNOWN until someone runs it against that TSA with that TSA's CA file.
* Needs the `openssl` binary on PATH. Without it every call fails closed (AnchorNotConfigured).
* The stamp covers the chain prefix up to tip_seq. Records appended later (including the
  `anchor.timestamp` record itself) are covered only by the NEXT stamp.
* A TSA proves time of existence, not truth of the content.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from . import pipeline_bridge as pb
from .hashchain import canonical_json, verify_chain

ANCHOR_TS_TYPE = "anchor.timestamp"
SCHEMA = "ola.anchor-timestamp/1"
MAX_REPLY_BYTES = 256 * 1024

_SHA256_OID = bytes.fromhex("0609608648016503040201")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class AnchorNotConfigured(RuntimeError):
    """Missing/invalid configuration or tooling: HTTP 503, fail closed."""


class AnchorFailed(RuntimeError):
    """The TSA did not return a token that verifies: HTTP 502. Nothing is recorded."""


@dataclass(frozen=True)
class AnchorConfig:
    url: str
    ca_file: Path
    directory: Path
    timeout: float


# ------------------------------------------------------------------ configuration
def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def config_from_env() -> AnchorConfig:
    url = os.getenv("OLA_TSA_URL", "").strip()
    ca = os.getenv("OLA_TSA_CA_FILE", "").strip()
    if not url or not ca:
        raise AnchorNotConfigured("OLA_TSA_URL and OLA_TSA_CA_FILE are both required for the external anchor")
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("https", "http") or not parsed.hostname:
        raise AnchorNotConfigured("OLA_TSA_URL must be an http(s) URL")
    if parsed.scheme == "http" and not _is_loopback(parsed.hostname):
        raise AnchorNotConfigured("OLA_TSA_URL must be https (plain http is accepted only for loopback)")
    if parsed.username or parsed.password:
        raise AnchorNotConfigured("OLA_TSA_URL must not embed credentials")
    ca_path = Path(ca)
    try:
        if b"BEGIN CERTIFICATE" not in ca_path.read_bytes():
            raise AnchorNotConfigured("OLA_TSA_CA_FILE holds no PEM certificate")
    except OSError:
        raise AnchorNotConfigured("OLA_TSA_CA_FILE is not readable") from None
    try:
        timeout = float(os.getenv("OLA_TSA_TIMEOUT_S", "").strip() or "20")
    except ValueError:
        raise AnchorNotConfigured("OLA_TSA_TIMEOUT_S must be a number") from None
    if not 0 < timeout <= 120:
        raise AnchorNotConfigured("OLA_TSA_TIMEOUT_S must be in (0, 120]")
    if shutil.which("openssl") is None:
        raise AnchorNotConfigured("the openssl binary is required to verify time-stamp tokens and was not found")
    return AnchorConfig(url, ca_path, Path(os.getenv("OLA_ANCHOR_DIR", "./ola_anchor")), timeout)


# ------------------------------------------------------------------ RFC 3161 request
def tip_digest(tenant_id: str, tip_seq: int, tip_hash: str) -> bytes:
    material = canonical_json({"schema": SCHEMA, "tenant_id": tenant_id, "tip_seq": tip_seq, "tip_hash": tip_hash})
    return hashlib.sha256(material.encode("utf-8")).digest()


def new_nonce() -> int:
    return secrets.randbits(63) | (1 << 62)          # positive, fixed length (8 DER bytes), never zero


def build_request(digest: bytes, nonce: int) -> bytes:
    """DER TimeStampReq: version 1, SHA-256 imprint, nonce, certReq=TRUE (fixed layout, 69 bytes)."""
    if len(digest) != 32:
        raise ValueError("digest must be 32 bytes (SHA-256)")
    if not 0 < nonce < (1 << 63):
        raise ValueError("nonce out of range")
    algorithm = b"\x30\x0d" + _SHA256_OID[:11] + b"\x05\x00"          # AlgorithmIdentifier{sha256, NULL}
    imprint = b"\x30\x31" + algorithm + b"\x04\x20" + digest
    body = b"\x02\x01\x01" + imprint + b"\x02\x08" + nonce.to_bytes(8, "big") + b"\x01\x01\xff"
    return b"\x30" + bytes([len(body)]) + body


# ------------------------------------------------------------------ openssl
def _openssl(*args: str, timeout: float = 30) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(["openssl", *args], capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise AnchorNotConfigured(f"openssl could not be run ({type(exc).__name__})") from exc


def _verify_token(tsq: bytes, tsr: bytes, ca_file: Path) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory() as tmp:
        q, r = Path(tmp, "q.tsq"), Path(tmp, "r.tsr")
        q.write_bytes(tsq)
        r.write_bytes(tsr)
        done = _openssl("ts", "-verify", "-queryfile", str(q), "-in", str(r), "-CAfile", str(ca_file))
        if done.returncode == 0 and b"Verification: OK" in done.stdout + done.stderr:
            return True, "ok"
        detail = (done.stderr or done.stdout).decode("utf-8", "replace").strip().splitlines()
        return False, (detail[-1] if detail else "openssl ts -verify failed")[:200]


def _token_time(tsr: bytes) -> Optional[str]:
    with tempfile.TemporaryDirectory() as tmp:
        r = Path(tmp, "r.tsr")
        r.write_bytes(tsr)
        done = _openssl("ts", "-reply", "-in", str(r), "-text")
    if done.returncode != 0:
        return None
    m = re.search(r"^Time stamp:\s*(.+)$", done.stdout.decode("utf-8", "replace"), re.M)
    return m.group(1).strip() if m else None


def _post(cfg: AnchorConfig, tsq: bytes) -> bytes:
    req = urllib.request.Request(cfg.url, data=tsq, method="POST",
                                 headers={"Content-Type": "application/timestamp-query",
                                          "Accept": "application/timestamp-reply"})
    try:
        with urllib.request.urlopen(req, timeout=cfg.timeout) as resp:      # noqa: S310 - scheme checked above
            body = resp.read(MAX_REPLY_BYTES + 1)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise AnchorFailed(f"the TSA could not be reached ({type(exc).__name__})") from exc
    if not body or len(body) > MAX_REPLY_BYTES:
        raise AnchorFailed("the TSA returned an empty or oversized reply")
    return body


# ------------------------------------------------------------------ stamp + verify
def _file_stem(tip_seq: int) -> str:
    return f"tip-{int(tip_seq):012d}"


def _tenant_dir(cfg_dir: Path, tenant_id: str) -> Path:
    pb._check_tenant(tenant_id)
    return cfg_dir / tenant_id


def timestamp_tip(tenant_id: str) -> Dict[str, Any]:
    """Stamp the current chain tip. Raises AnchorFailed unless the token verifies against OLA_TSA_CA_FILE."""
    cfg = config_from_env()
    chain = pb.load_chain(tenant_id)
    if not chain:
        raise AnchorFailed("the tenant chain is empty: nothing to anchor")
    ok, why = verify_chain(chain)
    if not ok:
        raise AnchorFailed(f"the tenant chain does not verify ({why}): refusing to anchor a broken chain")
    tip = chain[-1]
    digest, nonce = tip_digest(tenant_id, tip["seq"], tip["record_hash"]), new_nonce()
    tsq = build_request(digest, nonce)
    tsr = _post(cfg, tsq)
    valid, detail = _verify_token(tsq, tsr, cfg.ca_file)
    if not valid:
        raise AnchorFailed(f"the TSA reply does not verify against the configured CA: {detail}")
    directory = _tenant_dir(cfg.directory, tenant_id)
    directory.mkdir(parents=True, exist_ok=True)
    stem = _file_stem(tip["seq"])
    (directory / f"{stem}.tsq").write_bytes(tsq)
    (directory / f"{stem}.tsr").write_bytes(tsr)
    rec = pb.append_evidence(tenant_id, ANCHOR_TS_TYPE, {
        "schema": SCHEMA, "tip_seq": tip["seq"], "tip_hash": tip["record_hash"],
        "digest": digest.hex(), "nonce": nonce,
        "tsq_sha256": hashlib.sha256(tsq).hexdigest(), "tsr_sha256": hashlib.sha256(tsr).hexdigest(),
        "tsa_host": urllib.parse.urlsplit(cfg.url).hostname, "gen_time": _token_time(tsr),
        "ca_sha256": hashlib.sha256(cfg.ca_file.read_bytes()).hexdigest(),
    })
    return {"status": "ANCHORED", "anchor_seq": rec["seq"], "tip_seq": tip["seq"], "tip_hash": tip["record_hash"],
            "gen_time": _token_time(tsr), "tsa_host": urllib.parse.urlsplit(cfg.url).hostname}


def _fail(reason: str, **extra: Any) -> Dict[str, Any]:
    return {"status": "BLOCK", "reason": reason, **extra}


def verify_timestamp(tenant_id: str, anchor_seq: int, *, cfg: Optional[AnchorConfig] = None) -> Dict[str, Any]:
    """Independent re-check of one `anchor.timestamp` record. VERIFIED only if EVERY check holds:
    chain intact, record is an anchor of this tenant, tip hash still matches the chain, stored files match
    their recorded hashes, the request is exactly the one rebuilt from the chain, and openssl verifies the
    token against the CA file. Anything else is BLOCK (tampering) or UNKNOWN (cannot check)."""
    cfg = cfg or config_from_env()
    chain = pb.load_chain(tenant_id)
    ok, why = verify_chain(chain)
    if not ok:
        return _fail(f"the tenant chain does not verify ({why})")
    rec = next((r for r in chain if r["seq"] == anchor_seq and r["record_type"] == ANCHOR_TS_TYPE), None)
    if rec is None:
        return {"status": "UNKNOWN", "reason": "no such anchor.timestamp record"}
    try:
        p = json.loads(rec["payload_json"])
        tip_seq, tip_hash, nonce = int(p["tip_seq"]), str(p["tip_hash"]), int(p["nonce"])
        digest_hex, tsq_sha, tsr_sha = str(p["digest"]), str(p["tsq_sha256"]), str(p["tsr_sha256"])
    except (ValueError, KeyError, TypeError):
        return _fail("the anchor record is malformed")
    if not (0 <= tip_seq < anchor_seq) or not all(_HEX64.match(x) for x in (tip_hash, digest_hex, tsq_sha, tsr_sha)):
        return _fail("the anchor record is malformed")
    if chain[tip_seq]["record_hash"] != tip_hash:
        return _fail("the stamped tip no longer matches the chain")
    digest = tip_digest(tenant_id, tip_seq, tip_hash)
    if digest.hex() != digest_hex:
        return _fail("the stamped digest does not match the chain tip")
    stem = _file_stem(tip_seq)
    directory = _tenant_dir(cfg.directory, tenant_id)
    try:
        tsq, tsr = (directory / f"{stem}.tsq").read_bytes(), (directory / f"{stem}.tsr").read_bytes()
    except OSError:
        return {"status": "UNKNOWN", "reason": "the stored time-stamp files are missing"}
    if hashlib.sha256(tsq).hexdigest() != tsq_sha or hashlib.sha256(tsr).hexdigest() != tsr_sha:
        return _fail("the stored time-stamp files do not match the recorded hashes")
    if tsq != build_request(digest, nonce):
        return _fail("the stored request is not the one derived from the chain tip")
    valid, detail = _verify_token(tsq, tsr, cfg.ca_file)
    if not valid:
        return _fail(f"the token does not verify against the configured CA: {detail}")
    return {"status": "VERIFIED", "tip_seq": tip_seq, "tip_hash": tip_hash, "gen_time": _token_time(tsr),
            "checks": {"chain": True, "tip_matches": True, "files_match": True, "request_derived": True,
                       "token_signature_and_imprint": True}}
