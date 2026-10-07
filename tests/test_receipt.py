"""A receipt must let a customer re-check their session offline, and must fail when anything in it is changed."""
import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

from app.hashchain import canonical_json, verify_chain
from app.receipt import FORMAT, build_receipt

ROOT = Path(__file__).resolve().parents[1]


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


rp = _load("rp_helpers", ROOT / "tests" / "test_revenue_proof.py")
vr = _load("verify_receipt_tool", ROOT / "tools" / "verify_receipt.py")
env = rp.env                                  # the fixture, re-exported for this module
make_tenant, _paid = rp.make_tenant, rp._paid


@pytest.fixture
def receipt(env):
    tenant_id, key = make_tenant()
    session = _paid(env, tenant_id)
    _paid(env, tenant_id, live=False)          # another session in the same chain
    return tenant_id, key, session, build_receipt(tenant_id, session["id"])


def test_a_receipt_of_a_proven_session_is_consistent_offline(receipt):
    tenant_id, _, session, bundle = receipt
    assert bundle["format"] == FORMAT and bundle["session_id"] == session["id"] and bundle["anchor"] is None
    report = vr.verify(bundle)
    assert report["verdict"] == "CONSISTENT" and report["payment_mode_recorded"] == "LIVE" and all(report["checks"].values())
    assert report["anchored"] is None and any("self-consistent" in item for item in report["limits"])
    assert bundle["claims"]["status"] == "PROVEN" and len(bundle["limits"]) == 3 and len(bundle["not_observable"]) == 3


def test_the_verifier_and_the_application_agree_on_every_hash(receipt):
    _, _, _, bundle = receipt
    assert verify_chain(bundle["chain"]) == (True, "ok") and vr.chain_ok(bundle["chain"]) == (True, "ok")
    for row in bundle["chain"]:
        assert vr.record_hash(row["tenant_id"], row["seq"], row["prev_hash"], row["payload_json"], row["record_type"]) == row["record_hash"]
    assert vr.canonical({"b": "ł", "a": [1, 2]}) == canonical_json({"b": "ł", "a": [1, 2]})


def test_the_receipt_holds_the_chain_only_up_to_the_session_not_later_records(env):
    tenant_id, _ = make_tenant()
    first = _paid(env, tenant_id)
    later = _paid(env, tenant_id)
    bundle = build_receipt(tenant_id, first["id"])
    assert all(later["id"] not in row["payload_json"] for row in bundle["chain"])
    assert bundle["head_hash"] == bundle["chain"][-1]["record_hash"] and vr.verify(bundle)["verdict"] == "CONSISTENT"


def test_a_head_hash_published_elsewhere_anchors_the_receipt_and_a_wrong_one_does_not(receipt):
    _, _, _, bundle = receipt
    ok = vr.verify(bundle, bundle["head_hash"].upper())
    assert ok["verdict"] == "CONSISTENT" and ok["anchored"] is True
    bad = vr.verify(bundle, "0" * 64)
    assert bad["verdict"] == "INCONSISTENT" and bad["anchored"] is False


def _tamper_payload(bundle, record_type, mutate):
    out = copy.deepcopy(bundle)
    for row in out["chain"]:
        if row["record_type"] == record_type:
            payload = json.loads(row["payload_json"])
            mutate(payload)
            row["payload_json"] = canonical_json(payload)
    return out


@pytest.mark.parametrize("record_type, mutate", [
    ("stripe.payment_confirmed", lambda p: p.update(livemode=False)),                 # a live payment relabelled test
    ("stripe.ola_execution_completed", lambda p: p.update(computation="PERFORMED", ola_run_id="x")),
    ("revenue.result_served", lambda p: p.update(result_sha256="0" * 64)),
])
def test_changing_any_recorded_payload_breaks_the_chain(receipt, record_type, mutate):
    _, _, _, bundle = receipt
    out = _tamper_payload(bundle, record_type, mutate)
    assert vr.verify(out)["verdict"] == "INCONSISTENT" and not vr.verify(out)["checks"]["chain_intact"]


def test_a_forged_chain_that_is_internally_consistent_is_caught_by_the_cross_checks(receipt):
    """Rewrite a payload AND re-hash the whole chain: the hashes now verify, but the result digest no longer matches."""
    _, _, _, bundle = receipt
    out = copy.deepcopy(bundle)
    out["result"]["ola_status"] = "FORGED"                                             # the delivered result is changed
    assert vr.verify(out)["checks"]["served_digest_matches_result"] is False and vr.verify(out)["verdict"] == "INCONSISTENT"


def test_a_result_that_belongs_to_another_session_is_refused(receipt):
    _, _, _, bundle = receipt
    out = copy.deepcopy(bundle)
    out["result"]["checkout_session_id"] = "cs_other"
    assert vr.verify(out)["checks"]["result_bound_to_session"] is False


def test_dropping_or_reordering_records_and_a_wrong_head_are_detected(receipt):
    _, _, _, bundle = receipt
    for broken in (dict(bundle, chain=bundle["chain"][1:]), dict(bundle, chain=list(reversed(bundle["chain"]))),
                   dict(bundle, head_hash="f" * 64), dict(bundle, chain=bundle["chain"][:-1])):
        assert vr.verify(broken)["verdict"] == "INCONSISTENT"


def test_a_chain_mixing_in_another_tenant_is_refused(receipt):
    _, _, _, bundle = receipt
    out = copy.deepcopy(bundle)
    out["tenant_id"] = "someone-else"
    assert vr.verify(out)["checks"]["chain_tenant_consistent"] is False


def test_a_receipt_exists_only_for_a_paid_session_on_a_valid_chain(env):
    tenant_id, _ = make_tenant()
    assert build_receipt(tenant_id, "cs_nothing") is None
    session = _paid(env, tenant_id)
    other, _ = make_tenant()
    assert build_receipt(other, session["id"]) is None                                # tenant isolation
    assert build_receipt(tenant_id, session["id"]) is not None


def test_the_endpoint_needs_the_owners_key_and_returns_a_bundle_the_cli_accepts(env, tmp_path):
    tenant_id, key = make_tenant()
    other_id, other_key = make_tenant()
    session = _paid(env, tenant_id)
    url = f"/revenue/receipt/{session['id']}"
    assert rp.client.get(url).status_code == 401
    assert rp.client.get(url, headers={"x-api-key": other_key}).status_code == 404
    response = rp.client.get(url, headers={"x-api-key": key})
    assert response.status_code == 200
    path = tmp_path / "r.json"
    path.write_text(response.text)
    done = subprocess.run([sys.executable, str(ROOT / "tools" / "verify_receipt.py"), str(path)], capture_output=True, text=True)
    assert done.returncode == 0 and json.loads(done.stdout)["verdict"] == "CONSISTENT"
    edited = response.json()
    edited["result"]["ola_run_id"] = "tampered"
    path.write_text(json.dumps(edited))
    assert subprocess.run([sys.executable, str(ROOT / "tools" / "verify_receipt.py"), str(path)], capture_output=True).returncode == 1
    path.write_text("not json")
    assert subprocess.run([sys.executable, str(ROOT / "tools" / "verify_receipt.py"), str(path)], capture_output=True).returncode == 2


def test_the_verifier_imports_nothing_from_ola():
    import ast
    tree = ast.parse((ROOT / "tools" / "verify_receipt.py").read_text())
    names = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    names |= {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert names <= {"argparse", "hashlib", "json", "sys"}


# ------------------------------------------------------------------ the verifier alone, on hand-built chains
def _chain(rows, tenant="t"):
    """rows: [(record_type, payload_dict)] -> hash-linked records; ids are r0, r1, ..."""
    out, prev = [], vr.GENESIS
    for seq, (rtype, payload) in enumerate(rows):
        pj = canonical_json(payload)
        h = vr.record_hash(tenant, seq, prev, pj, rtype)
        out.append({"id": f"r{seq}", "tenant_id": tenant, "seq": seq, "record_type": rtype, "prev_hash": prev,
                    "record_hash": h, "payload_json": pj})
        prev = h
    return out


def _synthetic(pay=None, execution=None, served=None, result=None, extra_payments=()):
    session = "cs_1"
    result = {"checkout_session_id": session, "payment_evidence_id": "r0", "ola_run_id": "run-1", **(result or {})}
    digest = hashlib.sha256(canonical_json(result).encode()).hexdigest()
    rows = [("stripe.payment_confirmed", {"checkout_session_id": session, "livemode": True, **(pay or {})})]
    rows += [("stripe.payment_confirmed", {"checkout_session_id": session, "livemode": live}) for live in extra_payments]
    rows += [("stripe.ola_execution_completed", {"checkout_session_id": session, "payment_evidence_id": "r0",
                                                 "ola_run_id": "run-1", "computation": "PERFORMED", **(execution or {})}),
             ("revenue.result_served", {"session_id": session, "run_id": "run-1", "result_sha256": digest, **(served or {})})]
    chain = _chain(rows)
    return {"format": "ola.receipt/1", "tenant_id": "t", "session_id": session, "chain": chain,
            "head_hash": chain[-1]["record_hash"], "result": result, "limits": []}


def test_the_synthetic_receipt_is_consistent_so_each_negative_case_fails_for_one_reason():
    report = vr.verify(_synthetic())
    assert report["verdict"] == "CONSISTENT" and report["payment_mode_recorded"] == "LIVE"


@pytest.mark.parametrize("kwargs, failing", [
    ({"execution": {"payment_evidence_id": "r9"}}, "execution_points_at_payment"),
    ({"execution": {"computation": "NOT_PERFORMED"}}, "execution_performed"),
    ({"served": {"run_id": "run-2"}}, "served_digest_matches_result"),
    ({"served": {"result_sha256": "0" * 64}}, "served_digest_matches_result"),
    ({"result": {"payment_evidence_id": "r5"}}, "result_bound_to_session"),
    ({"result": {"ola_run_id": "run-2"}}, "result_bound_to_session"),
    ({"result": {"checkout_session_id": "cs_2"}}, "result_bound_to_session"),
])
def test_each_cross_reference_is_checked_on_its_own(kwargs, failing):
    report = vr.verify(_synthetic(**kwargs))
    assert report["checks"][failing] is False and report["verdict"] == "INCONSISTENT"


@pytest.mark.parametrize("live, mode", [(True, "LIVE"), (False, "TEST"), ("true", "UNKNOWN"), (1, "UNKNOWN"), (None, "UNKNOWN")])
def test_only_a_boolean_livemode_gives_a_mode(live, mode):
    assert vr.verify(_synthetic(pay={"livemode": live}))["payment_mode_recorded"] == mode


def test_the_first_payment_record_decides_the_mode():
    assert vr.verify(_synthetic(pay={"livemode": False}, extra_payments=(True,)))["payment_mode_recorded"] == "TEST"


def test_the_chain_check_alone_catches_gaps_reordering_wrong_predecessors_and_a_downgrade_to_v1():
    chain = _chain([("a.b", {"n": i}) for i in range(4)])
    assert vr.chain_ok(chain) == (True, "ok")
    assert not vr.chain_ok(chain[1:])[0] and not vr.chain_ok([chain[0], chain[2], chain[3]])[0]
    assert not vr.chain_ok([chain[0], chain[2], chain[1], chain[3]])[0]
    wrong_prev = copy.deepcopy(chain)
    wrong_prev[1]["prev_hash"] = "1" * 64
    assert not vr.chain_ok(wrong_prev)[0]
    downgraded = copy.deepcopy(chain)                           # the last record re-hashed the old v1 way after v2 began
    downgraded[3]["record_hash"] = vr.record_hash("t", 3, downgraded[3]["prev_hash"], downgraded[3]["payload_json"])
    assert not vr.chain_ok(downgraded)[0]
    legacy = [dict(r, record_type=None) for r in chain]         # a pure v1 chain still verifies
    prev = vr.GENESIS
    for seq, row in enumerate(legacy):
        row["prev_hash"], row["seq"] = prev, seq
        row["record_hash"] = prev = vr.record_hash("t", seq, prev, row["payload_json"])
    assert vr.chain_ok(legacy) == (True, "ok")


def test_another_format_is_unreadable_not_consistent(tmp_path):
    path = tmp_path / "r.json"
    path.write_text(json.dumps(dict(_synthetic(), format="something/else")))
    assert vr.main([str(path)]) == 2
