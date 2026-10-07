"""External anchor (RFC 3161) against a LOCAL TSA built with `openssl ts`.

This proves the request encoding, the fail-closed handling and the verification logic. It says NOTHING about a
commercial TSA (UNKNOWN until run against one with that TSA's CA file). Skipped without the openssl binary.
"""
import hashlib
import json
import os
import shutil
import subprocess
import threading
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import anchor_external as ax
from app import pipeline_bridge as pb
from app.database import SessionLocal
from app.hashchain import verify_chain
from app.main import app
from app.models import ApiKey, Tenant

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl binary not available (UNKNOWN)")

TSA_CNF = """
[ tsa ]
default_tsa = tsa_config
[ tsa_config ]
dir = {d}
serial = {d}/serial
crypto_device = builtin
signer_cert = {d}/tsa.pem
certs = {d}/tsa.pem
signer_key = {d}/tsa.key
signer_digest = sha256
default_policy = 1.2.3.4.1
other_policies = 1.2.3.4.5
digests = sha256
accuracy = secs:1
ordering = no
tsa_name = no
ess_cert_id_chain = no
ess_cert_id_alg = sha256
"""
EXT = "[ v3_tsa ]\nextendedKeyUsage = critical,timeStamping\nbasicConstraints = CA:FALSE\n"


def _sh(*args, cwd=None, inp=None):
    done = subprocess.run(list(args), cwd=cwd, input=inp, capture_output=True, check=False)
    assert done.returncode == 0, done.stderr.decode()
    return done.stdout


def make_pki(d: Path, name: str):
    """CA + TSA cert (EKU timeStamping, critical). Returns CA pem path."""
    d.mkdir(parents=True, exist_ok=True)
    (d / "serial").write_text("01\n")
    (d / "tsa.cnf").write_text(TSA_CNF.format(d=d))
    (d / "ext.cnf").write_text(EXT)
    _sh("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(d / "ca.key"), "-out",
        str(d / "ca.pem"), "-days", "2", "-subj", f"/CN=Test CA {name}")
    _sh("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(d / "tsa.key"), "-out", str(d / "tsa.csr"),
        "-subj", f"/CN=Test TSA {name}")
    _sh("openssl", "x509", "-req", "-in", str(d / "tsa.csr"), "-CA", str(d / "ca.pem"), "-CAkey", str(d / "ca.key"),
        "-CAcreateserial", "-out", str(d / "tsa.pem"), "-days", "2", "-extfile", str(d / "ext.cnf"),
        "-extensions", "v3_tsa")
    return d / "ca.pem"


class LocalTsa:
    def __init__(self, d: Path):
        self.d, self.mode, self.calls = d, "ok", []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                outer.calls.append(body)
                if outer.mode == "garbage":
                    reply = b"not a time-stamp reply"
                elif outer.mode == "empty":
                    reply = b""
                else:
                    reply = subprocess.run(
                        ["openssl", "ts", "-reply", "-config", str(d / "tsa.cnf"), "-section", "tsa_config",
                         "-queryfile", "/dev/stdin"], input=body, capture_output=True, check=False).stdout
                self.send_response(200)
                self.send_header("Content-Type", "application/timestamp-reply")
                self.send_header("Content-Length", str(len(reply)))
                self.end_headers()
                self.wfile.write(reply)

        self.httpd = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_port}/tsr"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    d = tmp_path_factory.mktemp("tsa")
    return d, make_pki(d, "A")


@pytest.fixture
def tsa(pki):
    t = LocalTsa(pki[0])
    yield t
    t.stop()


@pytest.fixture
def env(monkeypatch, tmp_path, tsa, pki):
    for k in list(os.environ):
        if k.startswith("OLA_") and k not in ("OLA_EG_DB_PATH", "OLA_RUNTIME_COMMIT"):
            monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("OLA_TSA_URL", tsa.url)
    monkeypatch.setenv("OLA_TSA_CA_FILE", str(pki[1]))
    monkeypatch.setenv("OLA_ANCHOR_DIR", str(tmp_path / "anchor"))
    return monkeypatch


from contextlib import contextmanager  # noqa: E402

_TRIGGER = ("CREATE TRIGGER IF NOT EXISTS evidence_no_update BEFORE UPDATE ON evidence_records "
            "BEGIN SELECT RAISE(ABORT, 'evidence_records is append-only'); END;")


@contextmanager
def updates_allowed():
    """Simulates an attacker with DB access. The append-only trigger is ALWAYS restored (shared test DB)."""
    from sqlalchemy import text
    with SessionLocal() as db:
        db.execute(text("DROP TRIGGER IF EXISTS evidence_no_update"))
        db.commit()
    try:
        yield
    finally:
        with SessionLocal() as db:
            db.execute(text(_TRIGGER))
            db.commit()


def make_tenant(records=3):
    tenant_id, key = str(uuid.uuid4()), "ax-" + uuid.uuid4().hex
    with SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name="ax"))
        db.add(ApiKey(id=str(uuid.uuid4()), tenant_id=tenant_id, key_hash=hashlib.sha256(key.encode()).hexdigest()))
        db.commit()
    for i in range(records):
        pb.append_evidence(tenant_id, "test.record", {"i": i})
    return tenant_id, key


# ------------------------------------------------------------------ request encoding
def test_request_is_parsed_by_openssl_with_our_digest_and_nonce(tmp_path):
    digest, nonce = hashlib.sha256(b"x").digest(), ax.new_nonce()
    tsq = ax.build_request(digest, nonce)
    assert len(tsq) == 69
    (tmp_path / "q.tsq").write_bytes(tsq)
    text = _sh("openssl", "ts", "-query", "-in", str(tmp_path / "q.tsq"), "-text").decode()
    assert "Hash Algorithm: sha256" in text
    assert digest.hex() in text.replace(" ", "").replace("\n", "").replace("0000-", "").lower() or \
        all(h in text.replace(" ", "").lower() for h in (digest.hex()[:8],))
    assert f"Nonce: 0x{nonce:X}" in text
    assert "Certificate required: yes" in text


@pytest.mark.parametrize("digest,nonce", [(b"short", 5), (bytes(32), 0), (bytes(32), 1 << 63)])
def test_request_rejects_bad_input(digest, nonce):
    with pytest.raises(ValueError):
        ax.build_request(digest, nonce)


# ------------------------------------------------------------------ configuration fails closed
@pytest.mark.parametrize("url,ca_ok", [
    ("", True), ("ftp://x/y", True), ("http://tsa.example.com/tsr", True),
    ("https://user:pw@tsa.example.com/tsr", True), ("https://tsa.example.com/tsr", False),
])
def test_bad_configuration_is_503_not_off(env, pki, url, ca_ok):
    env.setenv("OLA_TSA_URL", url)
    env.setenv("OLA_TSA_CA_FILE", str(pki[1]) if ca_ok else "/nonexistent.pem")
    _, key = make_tenant()
    r = TestClient(app).post("/anchor/timestamp", headers={"X-API-Key": key})
    assert r.status_code == 503, r.text


def test_missing_openssl_is_503(env, monkeypatch):
    _, key = make_tenant()
    monkeypatch.setattr(ax.shutil, "which", lambda *_: None)
    assert TestClient(app).post("/anchor/timestamp", headers={"X-API-Key": key}).status_code == 503


def test_path_is_not_a_leak(env, pki):
    env.setenv("OLA_TSA_CA_FILE", "/nonexistent.pem")
    _, key = make_tenant()
    r = TestClient(app).post("/anchor/timestamp", headers={"X-API-Key": key})
    assert str(pki[0]) not in r.text


# ------------------------------------------------------------------ happy path + independent verification
def test_stamp_and_verify_roundtrip(env, tsa):
    tenant, key = make_tenant()
    c = TestClient(app)
    r = c.post("/anchor/timestamp", headers={"X-API-Key": key})
    assert r.status_code == 200, r.text
    b = r.json()
    assert b["status"] == "ANCHORED" and b["tip_seq"] == 2 and b["anchor_seq"] == 3 and b["gen_time"]
    ok, why = verify_chain(pb.load_chain(tenant))
    assert ok, why
    v = c.get(f"/anchor/timestamp/{b['anchor_seq']}", headers={"X-API-Key": key}).json()
    assert v["status"] == "VERIFIED" and all(v["checks"].values()), v
    # only a digest reaches the TSA, never a payload
    assert len(tsa.calls) == 1 and len(tsa.calls[0]) == 69


def test_empty_chain_is_not_stamped(env):
    _, key = make_tenant(records=0)
    assert TestClient(app).post("/anchor/timestamp", headers={"X-API-Key": key}).status_code == 502


@pytest.mark.parametrize("mode", ["garbage", "empty"])
def test_bad_tsa_reply_records_nothing(env, tsa, mode):
    tenant, key = make_tenant()
    tsa.mode = mode
    before = len(pb.load_chain(tenant))
    r = TestClient(app).post("/anchor/timestamp", headers={"X-API-Key": key})
    assert r.status_code == 502, r.text
    assert len(pb.load_chain(tenant)) == before


def test_tsa_down_is_502_and_records_nothing(env, tsa):
    tenant, key = make_tenant()
    tsa.stop()
    before = len(pb.load_chain(tenant))
    assert TestClient(app).post("/anchor/timestamp", headers={"X-API-Key": key}).status_code == 502
    assert len(pb.load_chain(tenant)) == before


def test_reply_signed_by_an_untrusted_ca_is_rejected(env, tsa, tmp_path):
    other_ca = make_pki(tmp_path / "other", "B")            # configured trust anchor is a different CA
    env.setenv("OLA_TSA_CA_FILE", str(other_ca))
    tenant, key = make_tenant()
    before = len(pb.load_chain(tenant))
    r = TestClient(app).post("/anchor/timestamp", headers={"X-API-Key": key})
    assert r.status_code == 502 and "does not verify" in r.text
    assert len(pb.load_chain(tenant)) == before


def test_reply_for_another_request_is_rejected(env, tsa, monkeypatch):
    """A replayed old token (valid signature, different digest/nonce) must not verify for a new tip."""
    tenant, key = make_tenant()
    c = TestClient(app)
    assert c.post("/anchor/timestamp", headers={"X-API-Key": key}).status_code == 200
    old_tsr = next(Path(os.environ["OLA_ANCHOR_DIR"], tenant).glob("*.tsr")).read_bytes()
    pb.append_evidence(tenant, "test.record", {"more": 1})
    monkeypatch.setattr(ax, "_post", lambda cfg, tsq: old_tsr)
    r = c.post("/anchor/timestamp", headers={"X-API-Key": key})
    assert r.status_code == 502, r.text


# ------------------------------------------------------------------ tamper detection
def anchored(env):
    tenant, key = make_tenant()
    c = TestClient(app)
    b = c.post("/anchor/timestamp", headers={"X-API-Key": key}).json()
    d = Path(os.environ["OLA_ANCHOR_DIR"], tenant)
    return tenant, key, c, b["anchor_seq"], d


def verdict(c, key, seq):
    return c.get(f"/anchor/timestamp/{seq}", headers={"X-API-Key": key}).json()


@pytest.mark.parametrize("victim", [".tsq", ".tsr"])
def test_modified_stored_file_is_block(env, victim):
    _, key, c, seq, d = anchored(env)
    f = next(d.glob(f"*{victim}"))
    raw = f.read_bytes()
    f.write_bytes(raw[:-1] + bytes([raw[-1] ^ 0xFF]))        # always changes the byte (a fixed \x00 was a no-op 1 time in 256)
    v = verdict(c, key, seq)
    assert v["status"] == "BLOCK" and "recorded hashes" in v["reason"], v


def test_deleted_file_is_unknown_not_verified(env):
    _, key, c, seq, d = anchored(env)
    next(d.glob("*.tsr")).unlink()
    assert verdict(c, key, seq)["status"] == "UNKNOWN"


def test_rewritten_history_is_block(env):
    """Rewrite the stamped record (and recompute every later hash): the chain verifies, the stamp does not."""
    tenant, key, c, seq, d = anchored(env)
    from app.models import EvidenceRecord
    from app.hashchain import compute_record_hash
    from sqlalchemy import select
    with updates_allowed(), SessionLocal() as db:
        rows = db.scalars(select(EvidenceRecord).where(EvidenceRecord.tenant_id == tenant)
                          .order_by(EvidenceRecord.seq.asc())).all()
        prev = "0" * 64
        for r in rows:
            if r.seq == 1:
                r.payload_json = json.dumps({"i": "forged"}, sort_keys=True, separators=(",", ":"))
            r.prev_hash = prev
            r.record_hash = compute_record_hash(r.tenant_id, r.seq, prev, r.payload_json)
            prev = r.record_hash
        db.commit()
    ok, why = verify_chain(pb.load_chain(tenant))
    assert ok, why                                          # the chain alone is consistent again ...
    v = verdict(c, key, seq)
    assert v["status"] == "BLOCK" and v["reason"] in (
        "the stamped tip no longer matches the chain", "the anchor record is malformed"), v   # ... the stamp is not


def test_other_tenant_cannot_see_the_anchor(env):
    _, _, _, seq, _ = anchored(env)
    _, other_key = make_tenant()
    v = TestClient(app).get(f"/anchor/timestamp/{seq}", headers={"X-API-Key": other_key}).json()
    assert v["status"] != "VERIFIED"


def test_verification_never_trusts_a_stored_verdict(env):
    """Swapping the CA file for a different trust anchor turns a previously VERIFIED stamp into BLOCK."""
    _, key, c, seq, d = anchored(env)
    assert verdict(c, key, seq)["status"] == "VERIFIED"
    other = make_pki(d.parent / "otherca", "C")
    env.setenv("OLA_TSA_CA_FILE", str(other))
    assert verdict(c, key, seq)["status"] == "BLOCK"


def test_stamp_is_refused_for_a_broken_chain(env, tsa):
    tenant, key = make_tenant()
    from app.models import EvidenceRecord
    from sqlalchemy import select
    with updates_allowed(), SessionLocal() as db:
        row = db.scalar(select(EvidenceRecord).where(EvidenceRecord.tenant_id == tenant, EvidenceRecord.seq == 1))
        row.payload_json = '{"i":"forged"}'                 # hashes NOT recomputed -> chain breaks
        db.commit()
    assert not verify_chain(pb.load_chain(tenant))[0]
    r = TestClient(app).post("/anchor/timestamp", headers={"X-API-Key": key})
    assert r.status_code == 502 and "refusing to anchor" in r.text
    assert tsa.calls == []                                  # the digest of a broken chain never left the host


def test_record_whose_nonce_differs_from_the_stored_request_is_block(env):
    """Files and recorded hashes are consistent and the token is valid, but the record's nonce is not the one in
    the request: only the 'request derived from the chain' check can see it."""
    tenant, key = make_tenant()
    cfg = ax.config_from_env()
    chain = pb.load_chain(tenant)
    tip = chain[-1]
    digest = ax.tip_digest(tenant, tip["seq"], tip["record_hash"])
    real_nonce = ax.new_nonce()
    tsq = ax.build_request(digest, real_nonce)
    tsr = ax._post(cfg, tsq)
    d = cfg.directory / tenant
    d.mkdir(parents=True)
    (d / f"{ax._file_stem(tip['seq'])}.tsq").write_bytes(tsq)
    (d / f"{ax._file_stem(tip['seq'])}.tsr").write_bytes(tsr)
    rec = pb.append_evidence(tenant, ax.ANCHOR_TS_TYPE, {
        "schema": ax.SCHEMA, "tip_seq": tip["seq"], "tip_hash": tip["record_hash"], "digest": digest.hex(),
        "nonce": real_nonce ^ 1, "tsq_sha256": hashlib.sha256(tsq).hexdigest(),
        "tsr_sha256": hashlib.sha256(tsr).hexdigest()})
    assert ax.verify_timestamp(tenant, rec["seq"])["status"] == "BLOCK"
    # control: with the true nonce the very same files verify
    rec2 = pb.append_evidence(tenant, ax.ANCHOR_TS_TYPE, {
        "schema": ax.SCHEMA, "tip_seq": tip["seq"], "tip_hash": tip["record_hash"], "digest": digest.hex(),
        "nonce": real_nonce, "tsq_sha256": hashlib.sha256(tsq).hexdigest(),
        "tsr_sha256": hashlib.sha256(tsr).hexdigest()})
    assert ax.verify_timestamp(tenant, rec2["seq"])["status"] == "VERIFIED"
