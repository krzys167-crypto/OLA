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

    def verify_records(self, records, expected_commit, expected_task, expected_result, expected_provider=None, expected_model=None, expected_run_id=None, expected_invocation_type=None, expected_nonce=None):
        if not records:
            return IgorVerification("UNKNOWN", "missing evidence", {"chain": False})

        chain_ok, chain_reason = verify_chain(records)
        checks = {"chain": chain_ok}
        if not chain_ok:
            return IgorVerification("BLOCK", chain_reason, checks)

        payloads = [
            json.loads(record["payload_json"])
            for record in records
            if record.get("record_type", "").startswith("agent.")
        ]
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
        source_values = {payload.get("source_commit") for payload in payloads if payload.get("source_commit") is not None}
        legacy_values = {payload.get("commit") for payload in payloads if payload.get("commit") is not None}
        checks["source_commit"] = bool(expected_commit) and source_values == {expected_commit}
        checks["commit"] = checks["source_commit"] and (not legacy_values or legacy_values == {expected_commit})
        if not checks["source_commit"] or not checks["commit"]:
            return IgorVerification("BLOCK", "commit/source_commit provenance mismatch", checks)

        matching_task = bool(payloads) and all(payload.get("task") == expected_task for payload in payloads)
        checks["task"] = matching_task
        if not matching_task:
            return IgorVerification("BLOCK", "task mismatch", checks)

        result_payloads = [
            payload for payload in payloads
            if payload.get("agent") in {"codeact", "multi_agent"}
        ]
        matching_result = True
        codeact_payload = next(
            (payload for payload in result_payloads if payload.get("agent") == "codeact"),
            None,
        )
        final_payload = next(
            (payload for payload in result_payloads if payload.get("agent") == "multi_agent"),
            None,
        )
        if codeact_payload is not None:
            matching_result = matching_result and str(codeact_payload.get("tool_output")) == str(expected_result)
        if final_payload is not None:
            matching_result = matching_result and str(final_payload.get("final_result")) == str(expected_result)
        checks["result"] = matching_result
        if not matching_result:
            return IgorVerification("BLOCK", "result mismatch", checks)

        provenance_payloads = [
            payload for payload in payloads
            if payload.get("invocation_type") is not None
        ]
        if expected_provider is not None:
            checks["provider"] = bool(provenance_payloads) and all(
                payload.get("provider") == expected_provider
                and payload.get("invocation_type") == "real_llm"
                for payload in provenance_payloads
            )
            if not checks["provider"]:
                return IgorVerification("BLOCK", "provider provenance mismatch", checks)
            if expected_provider != "local":
                response_identity_count = sum(
                    1
                    for payload in provenance_payloads
                    if payload.get("response_id")
                    or payload.get("response_digest")
                    or payload.get("response_ids")
                    or payload.get("response_digests")
                )
                required_identity_count = len(payloads)
                if response_identity_count < required_identity_count:
                    return IgorVerification("BLOCK", "real LLM response identity incomplete", checks)
                checks["response_identity"] = (
                    response_identity_count == 6
                    if len(payloads) == 6
                    else response_identity_count >= required_identity_count
                )
        if expected_model is not None:
            checks["model"] = bool(provenance_payloads) and all(
                payload.get("model") == expected_model
                for payload in provenance_payloads
            )
            if not checks["model"]:
                return IgorVerification("BLOCK", "model provenance mismatch", checks)
        if expected_invocation_type is not None:
            checks["invocation_type"] = bool(provenance_payloads) and all(
                payload.get("invocation_type") == expected_invocation_type
                for payload in provenance_payloads
            )
            if not checks["invocation_type"]:
                return IgorVerification("BLOCK", "invocation type provenance mismatch", checks)
        if expected_nonce is not None:
            nonce_values = {payload.get("replay_nonce") for payload in payloads}
            checks["replay_nonce"] = nonce_values == {expected_nonce}
            if not checks["replay_nonce"]:
                return IgorVerification("BLOCK", "replay nonce provenance mismatch", checks)

        checks["evidence"] = True
        evidence_ids = tuple(record.get("id") for record in scoped_records if record.get("id"))
        return IgorVerification("VERIFIED", "independent verification passed", checks, evidence_ids)
