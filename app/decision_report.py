"""Policy-bound decision and evidence report for the OLA execution boundary.

This module deliberately separates:
1. evidence observed,
2. policy evaluation,
3. terminal decision,
4. human promotion,
5. report sealing.

It never upgrades UNKNOWN to VERIFIED.
"""
from dataclasses import dataclass
import hashlib

from .hashchain import canonical_json


@dataclass(frozen=True)
class PolicyDecision:
    status: str
    reason: str
    policy_id: str
    evidence_complete: bool
    human_required: bool


def evaluate_policy(*, nina_status: str, igor_status: str, evidence_count: int,
                    replay_status: str, human_approved: bool) -> PolicyDecision:
    """Evaluate the terminal policy without trusting a caller-provided verdict."""
    if evidence_count <= 0:
        return PolicyDecision("UNKNOWN", "no evidence", "OLA-POLICY-v1", False, True)
    if nina_status == "UNKNOWN" or igor_status == "UNKNOWN":
        return PolicyDecision("BLOCK", "UNKNOWN cannot be promoted", "OLA-POLICY-v1", False, True)
    if nina_status != "VERIFIED":
        return PolicyDecision("BLOCK", f"NINA status is {nina_status}", "OLA-POLICY-v1", False, True)
    if igor_status != "VERIFIED":
        return PolicyDecision("BLOCK", f"IGOR status is {igor_status}", "OLA-POLICY-v1", False, True)
    if replay_status not in {"PASS", "VERIFIED"}:
        return PolicyDecision("BLOCK", "replay verification did not pass", "OLA-POLICY-v1", False, True)
    return PolicyDecision(
        "VERIFIED",
        "policy conditions satisfied; independent human approval remains required",
        "OLA-POLICY-v1",
        True,
        True,
    )


def build_decision_report(*, task_id: str, run_id: str, task: str, nina: dict,
                          igor: dict, replay: dict | list, human_gate: dict,
                          evidence_ids: list[str], human_approved: bool,
                          human_actor: str, human_reason: str) -> dict:
    if isinstance(replay, dict):
        replay_status = str(replay.get("status", "UNKNOWN"))
    elif isinstance(replay, list):
        replay_status = "VERIFIED" if replay else "UNKNOWN"
    else:
        replay_status = "UNKNOWN"

    policy = evaluate_policy(
        nina_status=str(nina.get("status", "UNKNOWN")),
        igor_status=str(igor.get("status", "UNKNOWN")),
        evidence_count=len(evidence_ids),
        replay_status=replay_status,
        human_approved=human_approved,
    )
    body = {
        "schema": "ola.decision-report.v1",
        "task_id": task_id,
        "run_id": run_id,
        "task": task,
        "policy": {
            "id": policy.policy_id,
            "status": policy.status,
            "reason": policy.reason,
            "evidence_complete": policy.evidence_complete,
            "human_required": policy.human_required,
        },
        "nina": nina,
        "igor": igor,
        "replay": replay,
        "human_gate": human_gate,
        "evidence_ids": evidence_ids,
        "human_review": {
            "approved": human_approved,
            "actor": human_actor,
            "reason": human_reason,
        },
    }
    canonical = canonical_json(body)
    body["report_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return body
