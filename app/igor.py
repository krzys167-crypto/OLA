from dataclasses import dataclass
import json

from .hashchain import verify_chain


@dataclass(frozen=True)
class IgorVerification:
    status: str
    reason: str
    checks: dict
    evidence_ids: tuple[str, ...] = ()


class IgorVerifier:
    """Independent verifier for NINA/OLA evidence.

    Igor does not trust a caller-provided status. It derives its terminal
    classification from the supplied records and expected provenance/outcome.
    """

    def verify_records(self, records, expected_commit, expected_task, expected_result, expected_provider=None, expected_model=None, expected_run_id=None):
        if not records:
            return IgorVerification("UNKNOWN", "missing evidence", {"chain": False})

        chain_ok, chain_reason = verify_chain(records)
        checks = {"chain": chain_ok}
        if not chain_ok:
            return IgorVerification("BLOCK", chain_reason, checks)

        payloads = [json.loads(record["payload_json"]) for record in records]
        if expected_run_id is not None:
            payloads = [
                payload for payload in payloads
                if payload.get("run_id") == expected_run_id
            ]
            scoped_records = [
                record for record in records
                if json.loads(record["payload_json"]).get("run_id") == expected_run_id
            ]
        else:
            scoped_records = list(records)
        if not payloads:
            return IgorVerification("UNKNOWN", "missing current-run evidence", checks)
        provenance_values = {payload.get("commit") for payload in payloads if payload.get("commit") is not None}
        checks["commit"] = bool(expected_commit) and expected_commit in provenance_values
        if not checks["commit"]:
            return IgorVerification("BLOCK", "commit provenance mismatch", checks)

        matching_task = any(payload.get("task") == expected_task for payload in payloads)
        checks["task"] = matching_task
        if not matching_task:
            return IgorVerification("BLOCK", "task mismatch", checks)

        matching_result = any(
            str(payload.get("result")) == str(expected_result)
            or str(payload.get("tool_output")) == str(expected_result)
            for payload in payloads
        )
        checks["result"] = matching_result
        if not matching_result:
            return IgorVerification("BLOCK", "result mismatch", checks)

        provenance_payloads = [
            payload for payload in payloads
            if isinstance(payload.get("response_ids"), list)
            or payload.get("provider") is not None
            or payload.get("model") is not None
            or payload.get("invocation_type") is not None
        ]
        if expected_provider is not None:
            checks["provider"] = bool(provenance_payloads) and any(
                payload.get("provider") == expected_provider
                and payload.get("invocation_type") == "real_llm"
                for payload in provenance_payloads
            )
            if not checks["provider"]:
                return IgorVerification("BLOCK", "provider provenance mismatch", checks)
            if expected_provider != "local":
                response_ids = [
                    response_id
                    for payload in provenance_payloads
                    for response_id in payload.get("response_ids", [])
                ]
                if not response_ids:
                    return IgorVerification("BLOCK", "real LLM response ids missing", checks)
                checks["response_ids"] = True
        if expected_model is not None:
            checks["model"] = bool(provenance_payloads) and any(
                payload.get("model") == expected_model
                for payload in provenance_payloads
            )
            if not checks["model"]:
                return IgorVerification("BLOCK", "model provenance mismatch", checks)

        checks["evidence"] = True
        evidence_ids = tuple(record.get("id") for record in scoped_records if record.get("id"))
        return IgorVerification("VERIFIED", "independent verification passed", checks, evidence_ids)
