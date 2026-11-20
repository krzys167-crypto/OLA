import pytest

from app.capability_broker import ExecutionRequest, MockExecutor, VoucherIssuer, VoucherVerifier


SECRET = b"test-only-secret-material-32-bytes!"


def request(**overrides):
    values = dict(run_id="run-1", tenant_id="tenant-1", principal_id="user-1",
                  capability="calculate", arguments={"expression": "2+2"},
                  policy_version="policy-v1")
    values.update(overrides)
    return ExecutionRequest(**values)


def setup():
    issuer = VoucherIssuer(SECRET, {"calculate"}, ttl_seconds=30)
    verifier = VoucherVerifier(SECRET, clock=lambda: 100)
    executor = MockExecutor(verifier)
    req = request()
    voucher = issuer.issue(req, now=90)
    return issuer, verifier, executor, req, voucher


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


def test_expired_voucher_rejected():
    issuer = VoucherIssuer(SECRET, {"calculate"}, ttl_seconds=5)
    verifier = VoucherVerifier(SECRET, clock=lambda: 106)
    executor = MockExecutor(verifier)
    req = request()
    voucher = issuer.issue(req, now=100)
    with pytest.raises(PermissionError, match="expired"):
        executor.execute(voucher, req)
    assert executor.effects == []


def test_invalid_signature_rejected():
    _, _, executor, req, voucher = setup()
    from dataclasses import replace
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
        VoucherVerifier(b"short")
