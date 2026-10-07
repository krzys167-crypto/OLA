"""Regression tests for the third independent review (pipeline_bridge, external anchor, /audit). Each reproduced first."""
import datetime
import hashlib
import json
import os
import shutil
import threading
import time
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import anchor_external as ax
from app import pipeline_bridge as pb
from app.database import SessionLocal
from app.hashchain import verify_chain
from app.main import app
from app.models import ApiKey, Tenant
from tests.test_anchor_external import LocalTsa, TSA_CNF, make_tenant as ax_tenant  # noqa: F401
from tests.test_anchor_external import env, pki, tsa  # noqa: F401  (fixtures)

C = TestClient(app, raise_server_exceptions=False)
needs_openssl = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl binary not available (UNKNOWN)")


def make_tenant():
    tid, key = str(uuid.uuid4()), "r3-" + uuid.uuid4().hex
    with SessionLocal() as db:
        db.add(Tenant(id=tid, name="r3"))
        db.add(ApiKey(id=str(uuid.uuid4()), tenant_id=tid, key_hash=hashlib.sha256(key.encode()).hexdigest()))
        db.commit()
    return tid, key


# ------------------------------------------------------------------ item 1: qualification counts
def _qual(tmp_path, monkeypatch, **kw):
    from tests.test_pipeline_bridge import DATASET_SHA, JUDGE_DIGEST, write_qualification
    path = write_qualification(tmp_path, **kw)
    policy = pb.QualificationPolicy(path, DATASET_SHA, 0.15, 20, 0.5, 20)
    env = {"provider": "ollama-local", "model": "igor-test", "model_digest": JUDGE_DIGEST}
    return pb.judge_qualification(env, policy)


@pytest.mark.parametrize("n", [10 ** 200, 10 ** 400, 10 ** 20, 10 ** 9])
def test_item1_absurd_counts_are_refused_not_a_crash_and_not_a_qualification(tmp_path, monkeypatch, n):
    out = _qual(tmp_path, monkeypatch, k=0, n=n)
    assert out["state"] == "NOT_QUALIFIED" and "malformed" in out["reason"]
    out = _qual(tmp_path, monkeypatch, ck=n, cn=n)
    assert out["state"] == "NOT_QUALIFIED" and "malformed" in out["reason"]


def test_item1_a_normal_measurement_still_qualifies(tmp_path, monkeypatch):
    assert _qual(tmp_path, monkeypatch, k=0, n=26)["state"] == "QUALIFIED"


# ------------------------------------------------------------------ item 9: bad policy env is a 503, not a client 400
@pytest.mark.parametrize("name,val", [("OLA_MAX_ITERATIONS", "three"), ("OLA_MIN_QUALITY_SCORE", "high")])
def test_item9_a_bad_numeric_policy_value_is_a_misconfiguration(monkeypatch, tmp_path, name, val):
    monkeypatch.setenv(name, val)
    with pytest.raises(pb.PipelineNotConfigured):
        pb.build_config("t1", base=tmp_path)


# ------------------------------------------------------------------ item 7: /audit on a tenant that has other records
def test_item7_audit_is_verified_on_a_tenant_with_other_records():
    tid, key = make_tenant()
    H = {"X-API-Key": key}
    body = {"task": "t", "scenario": "fault_then_recovery"}
    assert C.post("/audit", headers=H, json=body).json()["status"] == "VERIFIED"
    assert C.post("/evidence", headers=H, json={"payload": {"a": 1}}).status_code == 200
    r = C.post("/audit", headers=H, json=body).json()                 # was FAILED evidence_chain_invalid
    assert r["status"] == "VERIFIED" and r["evidence_count"] == 5, r
    assert verify_chain(pb.load_chain(tid))[0]


# ------------------------------------------------------------------ item 8: two stamps of the same tip
@needs_openssl
def test_item8_two_concurrent_stamps_of_the_same_tip_keep_their_own_files(env, monkeypatch):
    tid, key = ax_tenant()
    real, state = pb.append_evidence, {"inner": False}

    def racing(tenant, rtype, payload, **kw):
        if rtype == ax.ANCHOR_TS_TYPE and not state["inner"]:
            state["inner"] = True
            state["first"] = ax.timestamp_tip(tid)          # a second stamp of the same tip finishes first
        return real(tenant, rtype, payload, **kw)

    monkeypatch.setattr(pb, "append_evidence", racing)
    outer = ax.timestamp_tip(tid)
    monkeypatch.setattr(pb, "append_evidence", real)
    for seq in (state["first"]["anchor_seq"], outer["anchor_seq"]):
        v = ax.verify_timestamp(tid, seq)
        assert v["status"] == "VERIFIED", (seq, v)


@needs_openssl
def test_item8_legacy_file_names_still_verify(env):
    tid, key = ax_tenant()
    r = ax.timestamp_tip(tid)
    d = Path(os.environ["OLA_ANCHOR_DIR"], tid)
    new = sorted(d.glob("tip-*-*.ts*"))
    assert len(new) == 2
    for f in new:                                                   # rename to the pre-fix names
        f.rename(d / (f.name.split("-")[0] + "-" + f.name.split("-")[1] + f.suffix))
    assert ax.verify_timestamp(tid, r["anchor_seq"])["status"] == "VERIFIED"


# ------------------------------------------------------------------ item 3: a TSA certificate that expired later
def test_item3_gen_time_is_parsed_from_the_token_format():
    assert ax._gen_epoch.__name__ == "_gen_epoch"
    import calendar
    orig = ax._token_time
    try:
        ax._token_time = lambda tsr: "Oct  5 19:38:23 2026 GMT"
        assert ax._gen_epoch(b"") == calendar.timegm((2026, 10, 5, 19, 38, 23))
        ax._token_time = lambda tsr: "Jan 31 00:00:00.123 2027 GMT"
        assert ax._gen_epoch(b"") == calendar.timegm((2027, 1, 31, 0, 0, 0))
        for bad in (None, "", "garbage", "Foo 5 19:38:23 2026 GMT", "Oct 40 19:38:23 2026 GMT"):
            ax._token_time = lambda tsr, b=bad: b
            assert ax._gen_epoch(b"") is None, bad
    finally:
        ax._token_time = orig


@needs_openssl
def test_item3_an_honest_anchor_is_not_tampering_after_the_tsa_certificate_expires(tmp_path, monkeypatch):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    d = tmp_path / "P"
    d.mkdir()
    key = lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048)           # noqa: E731
    name = lambda cn: x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])           # noqa: E731
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_k, tsa_k = key(), key()
    ca = (x509.CertificateBuilder().subject_name(name("CA")).issuer_name(name("CA")).public_key(ca_k.public_key())
          .serial_number(1).not_valid_before(now - datetime.timedelta(days=1))
          .not_valid_after(now + datetime.timedelta(days=30))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), True).sign(ca_k, hashes.SHA256()))
    life = 6
    cert = (x509.CertificateBuilder().subject_name(name("TSA")).issuer_name(name("CA")).public_key(tsa_k.public_key())
            .serial_number(2).not_valid_before(now - datetime.timedelta(hours=1))
            .not_valid_after(now + datetime.timedelta(seconds=life))
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), True).sign(ca_k, hashes.SHA256()))
    pem = serialization.Encoding.PEM
    (d / "ca.pem").write_bytes(ca.public_bytes(pem))
    (d / "tsa.pem").write_bytes(cert.public_bytes(pem))
    (d / "tsa.key").write_bytes(tsa_k.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (d / "serial").write_text("01\n")
    (d / "tsa.cnf").write_text(TSA_CNF.format(d=d))
    srv = LocalTsa(d)
    try:
        for k in list(os.environ):
            if k.startswith("OLA_") and k not in ("OLA_EG_DB_PATH", "OLA_RUNTIME_COMMIT"):
                monkeypatch.delenv(k, raising=False)
        monkeypatch.setenv("OLA_TSA_URL", srv.url)
        monkeypatch.setenv("OLA_TSA_CA_FILE", str(d / "ca.pem"))
        monkeypatch.setenv("OLA_ANCHOR_DIR", str(tmp_path / "anchor"))
        tid, _ = ax_tenant()
        r = ax.timestamp_tip(tid)
        assert ax.verify_timestamp(tid, r["anchor_seq"])["status"] == "VERIFIED"
        time.sleep(life + 2)                                          # the TSA certificate is now expired
        v = ax.verify_timestamp(tid, r["anchor_seq"])
        assert v["status"] == "VERIFIED", v                           # was BLOCK "certificate has expired"
    finally:
        srv.stop()


# ------------------------------------------------------------------ item 10: the anchor of a finished run keeps trying
def test_item10_the_anchor_append_keeps_retrying(tmp_path, monkeypatch):
    sd = tmp_path / "ses_0123456789abcdef01234567"
    sd.mkdir()
    seen = {}
    monkeypatch.setattr(pb, "inspect_session", lambda d: type("F", (), {"envelopes": [{"envelope_hash": "h"}]})())
    (sd / "final.json").write_text("{}")
    monkeypatch.setattr(pb, "append_evidence", lambda t, rt, p, **kw: seen.update(kw) or {"seq": 0})
    pb.anchor_session("t1", sd)
    assert seen.get("attempts", 0) >= 96
