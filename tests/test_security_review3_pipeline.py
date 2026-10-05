"""Third review, pipeline_bridge items 5 and 6 (fake Ollama, no network)."""
import json
import os
from pathlib import Path

from fastapi.testclient import TestClient

from app import pipeline_bridge as pb
from app.main import app
from ola_pipeline import attest
from ola_pipeline.attest import sign_session
from tests.test_pipeline_bridge import HUMAN, _key, anchors, env, fake, make_tenant, post, session_dir  # noqa: F401


def _unlock(sd: Path):
    os.chmod(sd, 0o755)
    for f in sd.rglob("*"):
        os.chmod(f, 0o755 if f.is_dir() else 0o644)


def _signed(env, tmp_path):
    keyfile, pub = _key(tmp_path, "a")
    env.setenv("OLA_SIGNING_KEY_FILE", str(keyfile))
    tenant, key = make_tenant()
    b = post(key, **HUMAN).json()
    assert b["pipeline"]["signed"] is True and b["status"] == "VERIFIED", b
    sd = session_dir(env, tenant, b["session_id"])
    _unlock(sd)
    return tenant, key, b["session_id"], sd, pub


def test_item5_a_stripped_attestation_is_block_even_without_a_pin(env, tmp_path):
    tenant, _, sid, sd, _ = _signed(env, tmp_path)
    assert pb.verify_anchor(tenant, sid)["status"] == "VERIFIED"
    (sd / "attestation.json").unlink()
    v = pb.verify_anchor(tenant, sid)
    assert v["status"] == "BLOCK" and "attestation" in v["reason"] and v["checks"]["attestation_matches_anchor"] is False


def test_item5_a_session_re_signed_with_another_key_is_block_even_without_a_pin(env, tmp_path):
    tenant, _, sid, sd, _ = _signed(env, tmp_path)
    other = attest.generate_keypair(tmp_path / "b")
    (sd / "attestation.json").unlink()
    sign_session(sd, Path(other["private_key_file"]))
    v = pb.verify_anchor(tenant, sid)
    assert v["status"] == "BLOCK" and "attestation" in v["reason"], v


def test_item5_an_unsigned_session_stays_verifiable_and_a_signature_added_later_is_a_change(env, tmp_path):
    tenant, key = make_tenant()
    b = post(key, **HUMAN).json()
    sid = b["session_id"]
    assert pb.verify_anchor(tenant, sid)["status"] == "VERIFIED"
    sd = session_dir(env, tenant, sid)
    _unlock(sd)
    k = attest.generate_keypair(tmp_path / "c")
    sign_session(sd, Path(k["private_key_file"]))
    assert pb.verify_anchor(tenant, sid)["status"] == "BLOCK"


def test_item6_the_replay_does_not_say_verified_next_to_a_tampered_session(env):
    tenant, key = make_tenant()
    b = post(key, **HUMAN).json()
    sid = b["session_id"]
    sd = session_dir(env, tenant, sid)
    _unlock(sd)
    art = next((sd / "artifacts").iterdir())
    art.write_bytes(art.read_bytes() + b"x")
    g = TestClient(app).get(f"/pipeline-session/{sid}", headers={"X-API-Key": key}).json()
    assert g["verification"]["status"] == "BLOCK"
    assert g["replay_verification"]["status"] == "BLOCK" and "scope" in g["replay_verification"]


def test_item6_an_intact_session_keeps_a_verified_replay_with_its_scope(env):
    tenant, key = make_tenant()
    b = post(key, **HUMAN).json()
    assert b["replay_verification"]["status"] == "VERIFIED" and "sealed anchor record only" in b["replay_verification"]["scope"]
    g = TestClient(app).get(f"/pipeline-session/{b['session_id']}", headers={"X-API-Key": key}).json()
    assert g["replay_verification"]["status"] == "VERIFIED"
