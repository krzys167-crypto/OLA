"""Ed25519 attestation of sessions: primitive correctness, signer, verifier, and the attacks it exists for.

Everything runs against the Ollama TEST DOUBLE, so sessions are classed TEST_DOUBLE (verifier: PARTIAL).
These tests prove the signature logic; they say nothing about model quality or live-runtime behaviour.
"""
import dataclasses
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from pipeline_helpers import igor_json
from ola_pipeline import Pipeline, Policy, attest, ed25519, verify_session
from ola_pipeline import verify as verify_mod
from ola_pipeline.errors import ReplayDetected, SigningError

ROOT = Path(__file__).resolve().parents[2]

# RFC 8032 section 7.1, TEST 1 (empty message)
RFC_SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
RFC_PUB = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
RFC_SIG = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821"
                        "590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")


# ------------------------------------------------------------------ helpers
def new_key(tmp_path, name="k"):
    d = tmp_path / "keys"
    d.mkdir(exist_ok=True)
    info = attest.generate_keypair(d / name)
    return d / name, bytes.fromhex(info["public_key"]), info


def session(fake, make_cfg, key_file, text="Paris is the capital of France.", **cfg_kw):
    fake.script("nina-test", text)
    fake.script("igor-test", igor_json("PASS", 92))
    cfg = dataclasses.replace(make_cfg(), signing_key_file=key_file, **cfg_kw)
    return Pipeline(cfg).run("What is the capital of France?")


def rewrite(path, fn):
    os.chmod(path, 0o644)
    fn(path)


def failures_of(rep):
    return " | ".join(rep["failures"])


# ------------------------------------------------------------------ primitive
def test_rfc8032_vector_both_implementations():
    assert ed25519.public_key(RFC_SEED) == RFC_PUB
    assert ed25519.sign(RFC_SEED, b"") == RFC_SIG
    assert ed25519.verify(RFC_PUB, b"", RFC_SIG)
    assert verify_mod.ed25519_verify(RFC_PUB, b"", RFC_SIG)        # the copy embedded in verify.py


def test_matches_cryptography_package_on_random_inputs():
    pytest.importorskip("cryptography")  # SKIPPED would mean UNKNOWN: no independent implementation here
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    for i in range(60):
        seed, msg = os.urandom(32), os.urandom(i % 70)
        key = Ed25519PrivateKey.from_private_bytes(seed)
        pub = key.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
        sig = key.sign(msg)
        assert ed25519.public_key(seed) == pub and ed25519.sign(seed, msg) == sig
        assert ed25519.verify(pub, msg, sig) and verify_mod.ed25519_verify(pub, msg, sig)
        bad = bytearray(sig)
        bad[i % 64] ^= 1 << (i % 8)
        with pytest.raises(InvalidSignature):
            Ed25519PublicKey.from_public_bytes(pub).verify(bytes(bad), msg)
        assert not ed25519.verify(pub, msg, bytes(bad)) and not verify_mod.ed25519_verify(pub, msg, bytes(bad))
        assert not verify_mod.ed25519_verify(pub, msg + b"x", sig)


def test_strictness_and_the_two_verifiers_agree_on_garbage():
    s = int.from_bytes(RFC_SIG[32:], "little")
    malleated = RFC_SIG[:32] + (s + ed25519.L).to_bytes(32, "little")     # S >= L: same point, must be rejected
    assert not ed25519.verify(RFC_PUB, b"", malleated) and not verify_mod.ed25519_verify(RFC_PUB, b"", malleated)
    noncanonical_y = (ed25519.P).to_bytes(32, "little")                  # y == p is not a canonical encoding
    cases = [(RFC_PUB[:31], RFC_SIG), (RFC_PUB, RFC_SIG[:63]), (noncanonical_y, RFC_SIG), (RFC_PUB, noncanonical_y + RFC_SIG[32:])]
    cases += [(os.urandom(32), os.urandom(64)) for _ in range(80)]
    for pub, sig in cases:
        assert ed25519.verify(pub, b"m", sig) == verify_mod.ed25519_verify(pub, b"m", sig) is False


# ------------------------------------------------------------------ signer + verifier
def test_unsigned_session_has_no_authenticity(fake, make_cfg):
    fake.script("igor-test", igor_json("PASS", 92))
    r = Pipeline(make_cfg()).run("t")
    assert r.attestation is None
    rep = verify_session(r.session_dir)
    assert rep["authenticity"] == "NONE" and rep["failures"] == [] and not (r.session_dir / "attestation.json").exists()


def test_signed_session_pinned_valid(fake, make_cfg, tmp_path):
    key, pub, info = new_key(tmp_path)
    r = session(fake, make_cfg, key)
    path = r.session_dir / "attestation.json"
    assert r.attestation["key_id"] == info["key_id"] and r.attestation["public_key"] == pub.hex()
    assert not (path.stat().st_mode & 0o222), "attestation must be read-only like all other evidence"
    rep = verify_session(r.session_dir, trusted_key=pub)
    assert rep["failures"] == [] and rep["authenticity"] == "PINNED_VALID"
    assert rep["overall"] == "PARTIAL"                                   # authenticity does not upgrade a test double
    assert rep["attestation"]["key_id"] == info["key_id"]


def test_unpinned_valid_is_not_authenticity(fake, make_cfg, tmp_path):
    key, pub, _ = new_key(tmp_path)
    rep = verify_session(session(fake, make_cfg, key).session_dir)
    assert rep["authenticity"] == "UNPINNED_VALID" and rep["failures"] == []
    assert any("NOT pinned" in w for w in rep["warnings"])


def test_pinned_with_a_different_key_fails(fake, make_cfg, tmp_path):
    key, _, _ = new_key(tmp_path, "mine")
    _, other_pub, _ = new_key(tmp_path, "other")
    rep = verify_session(session(fake, make_cfg, key).session_dir, trusted_key=other_pub)
    assert rep["overall"] == "FAILED" and rep["authenticity"] == "INVALID"
    assert "different key than the pinned" in failures_of(rep)


def test_consistent_forgery_passes_unpinned_and_is_caught_only_by_the_pin(fake, make_cfg, tmp_path):
    """The point of the whole feature, stated as a test.
    B is a fully self-consistent session (real chain, real hashes). An attacker who controls the
    directory can also sign it with their OWN key. Without a pin that is indistinguishable from a
    genuine signed session; with the victim's public key pinned it fails."""
    victim_key, victim_pub, _ = new_key(tmp_path, "victim")
    attacker_key, _, _ = new_key(tmp_path, "attacker")
    forged = session(fake, make_cfg, None, text="Berlin is the capital of France.")        # B, unsigned
    assert verify_session(forged.session_dir)["failures"] == []                             # consistency alone: passes
    attest.sign_session(forged.session_dir, attacker_key)                                    # attacker re-signs
    assert verify_session(forged.session_dir)["authenticity"] == "UNPINNED_VALID"           # documented limitation
    rep = verify_session(forged.session_dir, trusted_key=victim_pub)
    assert rep["overall"] == "FAILED" and "different key than the pinned" in failures_of(rep)
    unsigned = session(fake, make_cfg, None, text="Berlin again.")
    assert "missing" in failures_of(verify_session(unsigned.session_dir, trusted_key=victim_pub))


def test_splicing_a_genuine_attestation_onto_another_session_fails(fake, make_cfg, tmp_path):
    key, pub, _ = new_key(tmp_path)
    a = session(fake, make_cfg, key, text="Paris is the capital of France.")
    b = session(fake, make_cfg, None, text="Berlin is the capital of France.")
    shutil.copy(a.session_dir / "attestation.json", b.session_dir / "attestation.json")
    rep = verify_session(b.session_dir, trusted_key=pub)
    assert rep["overall"] == "FAILED" and rep["authenticity"] == "INVALID"
    msg = failures_of(rep)
    assert "does not match the session on disk" in msg and "chain_head" in msg and "session_id" in msg


@pytest.mark.parametrize("name", ["flip_signature", "gate_state", "chain_head", "signed_at", "swap_public_key",
                                  "schema", "garbage", "key_id"])
def test_tampering_with_the_attestation_is_detected(fake, make_cfg, tmp_path, name):
    key, pub, _ = new_key(tmp_path)
    _, other_pub, other_info = new_key(tmp_path, "other")
    r = session(fake, make_cfg, key)
    path = r.session_dir / "attestation.json"

    def mutate(p):
        if name == "garbage":
            p.write_text("{ not json")
            return
        att = json.loads(p.read_text())
        if name == "flip_signature":
            sig = bytearray(bytes.fromhex(att["signature"]))
            sig[10] ^= 1
            att["signature"] = sig.hex()
        elif name == "gate_state":
            att["payload"]["gate_state"] = "PASS" if att["payload"]["gate_state"] != "PASS" else "BLOCKED"
        elif name == "chain_head":
            att["payload"]["chain_head"] = "0" * 64
        elif name == "signed_at":
            att["payload"]["signed_at"] = "2020-01-01T00:00:00+00:00"       # payload altered, signature not
        elif name == "swap_public_key":
            att["public_key"], att["key_id"] = other_pub.hex(), other_info["key_id"]
        elif name == "schema":
            att["schema"] = "ola.attestation/999"
        elif name == "key_id":
            att["key_id"] = "0" * 64
        p.write_text(json.dumps(att))

    rewrite(path, mutate)
    for trusted in (None, pub):
        rep = verify_session(r.session_dir, trusted_key=trusted)
        assert rep["overall"] == "FAILED" and rep["authenticity"] == "INVALID", (name, trusted, rep["failures"])


def test_modifying_final_json_after_signing_is_detected(fake, make_cfg, tmp_path):
    key, pub, _ = new_key(tmp_path)
    r = session(fake, make_cfg, key)
    rewrite(r.session_dir / "final.json", lambda p: p.write_text(p.read_text() + "\n"))   # whitespace only
    rep = verify_session(r.session_dir, trusted_key=pub)
    assert rep["overall"] == "FAILED" and "final_sha256" in failures_of(rep)


def test_deleting_the_attestation_fails_when_a_key_is_pinned(fake, make_cfg, tmp_path):
    key, pub, _ = new_key(tmp_path)
    r = session(fake, make_cfg, key)
    os.remove(r.session_dir / "attestation.json")
    assert verify_session(r.session_dir)["authenticity"] == "NONE"                      # unpinned: nothing claimed
    rep = verify_session(r.session_dir, trusted_key=pub)
    assert rep["overall"] == "FAILED" and "missing" in failures_of(rep)


def test_both_signer_implementations_produce_verifiable_attestations(fake, make_cfg, tmp_path):
    pytest.importorskip("cryptography")
    key, pub, _ = new_key(tmp_path)
    impls = {}
    for pure in (False, True):
        r = session(fake, make_cfg, None, text=f"answer pure={pure}")
        att = attest.sign_session(r.session_dir, key, prefer_pure=pure)
        impls[pure] = att["signer_impl"]
        rep = verify_session(r.session_dir, trusted_key=pub)
        assert rep["failures"] == [] and rep["authenticity"] == "PINNED_VALID"
    assert impls[False] == "cryptography" and "pure-python" in impls[True]


def test_domain_separation_is_part_of_the_wire_format(fake, make_cfg, tmp_path):
    """Signer and verifier share ATT_DOMAIN, so removing it from both would change nothing visible.
    Pin the constant, and prove a valid signature over the SAME payload without the domain prefix is rejected."""
    assert verify_mod.ATT_DOMAIN == b"ola.attestation/1\n"
    seed_hex = (new_key(tmp_path)[0]).read_text().strip()
    seed = bytes.fromhex(seed_hex)
    pub = ed25519.public_key(seed)
    r = session(fake, make_cfg, None, text="unsigned base")
    from ola_pipeline.hashing import canonical_bytes, sha256_hex
    from ola_pipeline.vault import EvidenceVault
    facts = verify_mod.inspect_session(r.session_dir)
    final_bytes = (r.session_dir / "final.json").read_bytes()
    payload = verify_mod.attestation_payload(r.session_dir.name, facts.envelopes[-1]["envelope_hash"], final_bytes,
                                             json.loads(final_bytes), pub.hex(), "2026-10-04T00:00:00+00:00")
    forged = ed25519.sign(seed, canonical_bytes(payload))                 # no domain prefix
    assert ed25519.verify(pub, canonical_bytes(payload), forged)           # a perfectly valid Ed25519 signature...
    EvidenceVault.write_attestation_to(r.session_dir, {
        "schema": verify_mod.ATT_SCHEMA, "algorithm": "Ed25519", "key_id": sha256_hex(pub),
        "public_key": pub.hex(), "signer_impl": "test", "payload": payload, "signature": forged.hex()})
    rep = verify_session(r.session_dir, trusted_key=pub)                   # ...that the verifier must refuse
    assert rep["overall"] == "FAILED" and "signature is invalid" in failures_of(rep)


def test_signing_twice_is_refused(fake, make_cfg, tmp_path):
    key, _, _ = new_key(tmp_path)
    r = session(fake, make_cfg, key)
    with pytest.raises(ReplayDetected):
        attest.sign_session(r.session_dir, key)


# ------------------------------------------------------------------ key hygiene + fail-closed
def test_key_must_not_live_inside_the_vault(fake, make_cfg, tmp_path):
    vault = tmp_path / "vault"
    vault.mkdir()
    info = attest.generate_keypair(vault / "inside.key")
    with pytest.raises(SigningError) as ei:
        session(fake, make_cfg, Path(info["private_key_file"]))
    assert "inside the evidence vault" in str(ei.value)
    assert ei.value.run is not None and not (ei.value.run.session_dir / "attestation.json").exists()


def test_group_readable_key_is_refused_and_nothing_leaks(fake, make_cfg, tmp_path):
    key, _, _ = new_key(tmp_path)
    seed_hex = key.read_text().strip()
    os.chmod(key, 0o644)
    with pytest.raises(SigningError) as ei:
        session(fake, make_cfg, key)
    assert "group/others" in str(ei.value) and seed_hex not in str(ei.value)
    bad = tmp_path / "keys" / "bad"
    bad.write_text("this-is-secret-but-not-hex-0123456789\n")
    os.chmod(bad, 0o600)
    with pytest.raises(SigningError) as ei:
        attest.load_seed(bad)
    assert "secret" not in str(ei.value) and "0123456789" not in str(ei.value)


def test_private_key_never_appears_in_any_evidence_file(fake, make_cfg, tmp_path):
    key, _, _ = new_key(tmp_path)
    seed_hex = key.read_text().strip()
    r = session(fake, make_cfg, key)
    hits = [str(p) for p in (tmp_path / "vault").rglob("*") if p.is_file() and seed_hex.encode() in p.read_bytes()]
    assert hits == []


def test_signing_failure_is_fail_closed_not_silent(fake, make_cfg, tmp_path):
    _, pub, _ = new_key(tmp_path)
    with pytest.raises(SigningError) as ei:
        session(fake, make_cfg, tmp_path / "keys" / "does-not-exist")
    unsigned = ei.value.run
    assert unsigned is not None and unsigned.attestation is None and unsigned.final["gate_state"] in ("PASS", "BLOCKED", "REVIEW_REQUIRED")
    rep = verify_session(unsigned.session_dir, trusted_key=pub)
    assert rep["overall"] == "FAILED" and "missing" in failures_of(rep)


def test_keygen_modes_and_no_overwrite(tmp_path):
    info = attest.generate_keypair(tmp_path / "k")
    assert stat.S_IMODE((tmp_path / "k").stat().st_mode) == 0o600
    assert (tmp_path / "k.pub").read_text().strip() == info["public_key"] == ed25519.public_key(
        bytes.fromhex((tmp_path / "k").read_text().strip())).hex()
    with pytest.raises(SigningError):
        attest.generate_keypair(tmp_path / "k")


def test_keygen_leftover_pub_does_not_leave_orphan_private_key(tmp_path):
    (tmp_path / "k.pub").write_text("leftover\n")
    with pytest.raises(SigningError, match="refusing to overwrite"):
        attest.generate_keypair(tmp_path / "k")
    assert not (tmp_path / "k").exists()                      # no private key without its public half
    assert (tmp_path / "k.pub").read_text() == "leftover\n"   # and the existing file is untouched


def test_keygen_race_on_pub_removes_the_private_key_it_just_created(tmp_path, monkeypatch):
    real_open = os.open

    def racing_open(path, flags, mode=0o777, *a, **kw):
        if str(path).endswith(".pub"):                         # someone creates k.pub between our check and our open
            raise FileExistsError(path)
        return real_open(path, flags, mode, *a, **kw)

    monkeypatch.setattr(os, "open", racing_open)
    with pytest.raises(SigningError, match="refusing to overwrite"):
        attest.generate_keypair(tmp_path / "k")
    assert not (tmp_path / "k").exists()


def test_keygen_refuses_dangling_symlink_target(tmp_path):
    (tmp_path / "k").symlink_to(tmp_path / "nowhere")        # lexists() sees it, exists() would not
    with pytest.raises(SigningError, match="refusing to overwrite"):
        attest.generate_keypair(tmp_path / "k")
    assert not (tmp_path / "nowhere").exists() and not (tmp_path / "k.pub").exists()


# ------------------------------------------------------------------ CLI + standalone verifier
def _cli(args, env=None, cwd=ROOT):
    return subprocess.run([sys.executable, "-m", "ola_pipeline", *args], capture_output=True, text=True,
                          cwd=str(cwd), env={**os.environ, **(env or {})})


def test_cli_keygen_then_standalone_verify_with_pinned_key(fake, make_cfg, tmp_path):
    p = _cli(["keygen", "--out", str(tmp_path / "cli.key")])
    assert p.returncode == 0 and json.loads(p.stdout)["public_key"] == (tmp_path / "cli.key.pub").read_text().strip()
    assert _cli(["keygen", "--out", str(tmp_path / "cli.key")]).returncode == 1          # refuses to overwrite
    pub_hex = (tmp_path / "cli.key.pub").read_text().strip()
    r = session(fake, make_cfg, tmp_path / "cli.key")

    lone = tmp_path / "elsewhere"
    lone.mkdir()
    shutil.copy(ROOT / "ola_pipeline" / "verify.py", lone / "verify.py")              # verifier copied ALONE
    run = lambda *a: subprocess.run([sys.executable, "-I", str(lone / "verify.py"), str(r.session_dir), *a],
                                    capture_output=True, text=True)
    ok = run("--trusted-key", pub_hex)
    assert ok.returncode == 3 and "authenticity=PINNED_VALID" in ok.stdout              # 3 = PARTIAL (test double)
    assert run("--trusted-key", str(tmp_path / "cli.key.pub")).returncode == 3            # key given as a file
    assert run("--trusted-key", "ab" * 32).returncode == 1                                # wrong key -> FAILED
    assert run("--trusted-key", "not-a-key").returncode == 4                              # usage error
    assert "authenticity=UNPINNED_VALID" in run().stdout

    rep = _cli(["report", str(r.session_dir)])
    assert "authenticity   : UNPINNED_VALID" in rep.stdout and "NOT pinned" in rep.stdout


def test_cli_run_reports_signing_status_and_failure(fake, tmp_path):
    fake.script("nina-test", "Paris.")
    fake.script("igor-test", igor_json("PASS", 92))
    base = {"OLA_NINA_PROVIDER": "ollama-local", "OLA_NINA_BASE_URL": fake.url, "OLA_NINA_MODEL": "nina-test",
            "OLA_IGOR_MODEL": "igor-test", "OLA_VAULT_DIR": str(tmp_path / "v")}
    key, _, info = new_key(tmp_path)
    ok = _cli(["run", "--task", "capital of France?"], {**base, "OLA_SIGNING_KEY_FILE": str(key)})
    assert f"attestation: SIGNED key_id={info['key_id']}" in ok.stderr
    none = _cli(["run", "--task", "capital of France?"], {**base, "OLA_VAULT_DIR": str(tmp_path / "v2")})
    assert "attestation: NONE" in none.stderr
    bad = _cli(["run", "--task", "capital of France?"],
               {**base, "OLA_VAULT_DIR": str(tmp_path / "v3"), "OLA_SIGNING_KEY_FILE": str(tmp_path / "nope")})
    assert bad.returncode == 1 and "signing requested but failed" in bad.stderr and "UNSIGNED" in bad.stderr
