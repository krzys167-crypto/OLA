import hashlib
import hmac
import json
from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor

import pytest

from app.capability_broker import (
    ExecutionRequest, MockExecutor, SQLiteReplayLedger, VoucherIssuer, VoucherVerifier,
)


SECRET = b"test-only-secret-material-32-bytes!"


def request(**overrides):
    values = dict(run_id="run-1", tenant_id="tenant-1", principal_id="user-1",
                  capability="calculate", arguments={"expression": "2+2"},
                  policy_version="policy-v1")
    values.update(overrides)
    return ExecutionRequest(**values)


def setup(ledger=None):
    issuer = VoucherIssuer(SECRET, {"calculate"}, ttl_seconds=30)
    verifier = VoucherVerifier(SECRET, {"calculate"}, replay_ledger=ledger, clock=lambda: 100)
    executor = MockExecutor(verifier)
    req = request()
    voucher = issuer.issue(req, now=90)
    return issuer, verifier, executor, req, voucher


def _voucher_body(voucher):
    return {
        "voucher_id": voucher.voucher_id,
        "run_id": voucher.run_id,
        "tenant_id": voucher.tenant_id,
        "principal_id": voucher.principal_id,
        "capability": voucher.capability,
        "arguments_digest": voucher.arguments_digest,
        "policy_version": voucher.policy_version,
        "issued_at": voucher.issued_at,
        "expires_at": voucher.expires_at,
        "nonce": voucher.nonce,
    }


def _resign(voucher, **changes):
    altered = replace(voucher, **changes)
    signature = hmac.new(SECRET, json.dumps(
        _voucher_body(altered), sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8"), hashlib.sha256).hexdigest()
    return replace(altered, signature=signature)


def test_valid_voucher_produces_one_mock_effect():
    _, _, executor, req, voucher = setup()
    result = executor.execute(voucher, req)
    assert result["status"] == "executed"
    assert len(executor.effects) == 1
    assert executor.effects[0]["run_id"] == req.run_id
    assert executor.effects[0]["tenant_id"] == req.tenant_id


@pytest.mark.parametrize("changed", [
    {"run_id": "run-other"},
    {"tenant_id": "tenant-other"},
    {"principal_id": "principal-other"},
    {"capability": "delete"},
    {"arguments": {"expression": "9*9"}},
    {"policy_version": "policy-v2"},
])
def test_scope_tampering_produces_zero_effects(changed):
    _, _, executor, req, voucher = setup()
    altered = request(**changed)
    with pytest.raises(PermissionError):
        executor.execute(voucher, altered)
    assert executor.effects == []


def test_replay_rejected():
    _, _, executor, req, voucher = setup()
    executor.execute(voucher, req)
    with pytest.raises(PermissionError, match="replay"):
        executor.execute(voucher, req)
    assert len(executor.effects) == 1


def test_nonce_reuse_rejected_even_with_different_voucher_id():
    _, verifier, executor, req, voucher = setup()
    executor.execute(voucher, req)
    replay = _resign(voucher, voucher_id="f" * 32)
    with pytest.raises(PermissionError, match="replay"):
        verifier.verify_and_consume(replay, req)
    assert len(executor.effects) == 1


def test_expired_voucher_rejected():
    issuer = VoucherIssuer(SECRET, {"calculate"}, ttl_seconds=5)
    verifier = VoucherVerifier(SECRET, {"calculate"}, clock=lambda: 106)
    executor = MockExecutor(verifier)
    req = request()
    voucher = issuer.issue(req, now=100)
    with pytest.raises(PermissionError, match="expired"):
        executor.execute(voucher, req)
    assert executor.effects == []


def test_future_voucher_rejected():
    issuer = VoucherIssuer(SECRET, {"calculate"}, ttl_seconds=5)
    verifier = VoucherVerifier(SECRET, {"calculate"}, clock=lambda: 100)
    req = request()
    voucher = issuer.issue(req, now=101)
    with pytest.raises(PermissionError, match="not yet valid"):
        verifier.verify_and_consume(voucher, req)


def test_verifier_enforces_its_own_capability_allowlist():
    issuer = VoucherIssuer(SECRET, {"delete"}, ttl_seconds=5)
    verifier = VoucherVerifier(SECRET, {"calculate"}, clock=lambda: 100)
    req = request(capability="delete")
    voucher = issuer.issue(req, now=90)
    with pytest.raises(PermissionError, match="allowlisted"):
        verifier.verify_and_consume(voucher, req)


def test_invalid_signature_rejected():
    _, _, executor, req, voucher = setup()
    altered = replace(voucher, signature="0" * 64)
    with pytest.raises(PermissionError, match="signature"):
        executor.execute(altered, req)
    assert executor.effects == []


def test_issuer_denies_unknown_capability():
    issuer = VoucherIssuer(SECRET, {"calculate"})
    with pytest.raises(PermissionError):
        issuer.issue(request(capability="delete"), now=1)


def test_short_or_missing_secret_rejected():
    with pytest.raises(ValueError):
        VoucherIssuer(b"short", {"calculate"})
    with pytest.raises(ValueError):
        VoucherVerifier(b"short", {"calculate"})


def test_durable_replay_rejected_across_verifier_instances(tmp_path):
    path = str(tmp_path / "replay.db")
    ledger1 = SQLiteReplayLedger(path)
    _, _, executor1, req, voucher = setup(ledger1)
    executor1.execute(voucher, req)

    ledger2 = SQLiteReplayLedger(path)
    verifier2 = VoucherVerifier(SECRET, {"calculate"}, replay_ledger=ledger2, clock=lambda: 100)
    with pytest.raises(PermissionError, match="replay"):
        verifier2.verify_and_consume(voucher, req)


def test_sqlite_ledger_consumes_nonce_atomically_across_workers(tmp_path):
    path = str(tmp_path / "shared-replay.db")
    _, _, _, req, voucher = setup(SQLiteReplayLedger(path))
    verifiers = [
        VoucherVerifier(SECRET, {"calculate"}, replay_ledger=SQLiteReplayLedger(path), clock=lambda: 100)
        for _ in range(2)
    ]
    def consume(verifier):
        try:
            verifier.verify_and_consume(voucher, req)
            return "accepted"
        except PermissionError:
            return "rejected"
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(consume, verifiers))
    assert sorted(outcomes) == ["accepted", "rejected"]
