from dataclasses import dataclass
from enum import Enum
from .igor_evidence_verifier import verify_chain


class RuleStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class RuleResult:
    status: RuleStatus
    reason: str


def rule_core_hash_001(records):
    if not records:
        return RuleResult(RuleStatus.UNKNOWN, "no evidence records")
    ok, reason = verify_chain(records)
    return RuleResult(RuleStatus.PASS if ok else RuleStatus.FAIL, reason)


def rule_cert_expiry_001(records):
    if not records:
        return RuleResult(RuleStatus.UNKNOWN, "no certificate evidence")
    for r in records:
        if r.get("record_type") != "certificate":
            continue
        try:
            payload = r["payload_json"]
            if '"expires_at"' not in payload:
                return RuleResult(RuleStatus.UNKNOWN, "certificate expiry is absent")
        except Exception:
            return RuleResult(RuleStatus.UNKNOWN, "malformed certificate evidence")
    return RuleResult(RuleStatus.UNKNOWN, "certificate evidence not sufficient for deterministic expiry decision")
