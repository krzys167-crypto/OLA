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

        # Group the chain-verified records by run. A claim (commit + task + result [+ provider/model]) has to be
        # carried by ONE record of ONE run: facts taken from different records or runs do not add up to evidence.
        groups: dict = {}
        for record in records:
            try:
                payload = json.loads(record["payload_json"])
            except (TypeError, ValueError):
                continue                      # chain-verified but not evidence: unattributable, never used
            if isinstance(payload, dict):
                groups.setdefault(payload.get("run_id"), []).append((record, payload))
        if expected_run_id is not None:
            groups = {expected_run_id: groups[expected_run_id]} if expected_run_id in groups else {}
        if not groups:
            return IgorVerification("UNKNOWN", "missing current-run evidence", checks)

        best = None
        for members in groups.values():
            verdict = self._verify_group(members, checks, expected_commit, expected_task, expected_result,
                                         expected_provider, expected_model)
            if verdict.status == "VERIFIED":
                return verdict
            if best is None or len(verdict.checks) >= len(best.checks):
                best = verdict
        return best

    @staticmethod
    def _same(actual, expected):
        """Type-strict equality; a missing value (None) never matches anything."""
        return actual is not None and type(actual) is type(expected) and actual == expected

    def _verify_group(self, members, base_checks, expected_commit, expected_task, expected_result,
                      expected_provider, expected_model):
        checks = dict(base_checks)
        candidates = [(r, p) for r, p in members if bool(expected_commit) and self._same(p.get("commit"), expected_commit)]
        checks["commit"] = bool(candidates)
        if not candidates:
            return IgorVerification("BLOCK", "commit provenance mismatch", checks)

        candidates = [(r, p) for r, p in candidates if self._same(p.get("task"), expected_task)]
        checks["task"] = bool(candidates)
        if not candidates:
            return IgorVerification("BLOCK", "task mismatch", checks)

        candidates = [(r, p) for r, p in candidates
                      if self._same(p.get("result"), expected_result) or self._same(p.get("tool_output"), expected_result)]
        checks["result"] = bool(candidates)
        if not candidates:
            return IgorVerification("BLOCK", "result mismatch", checks)

        def has_provenance(p):
            return (isinstance(p.get("response_ids"), list) or p.get("provider") is not None
                    or p.get("model") is not None or p.get("invocation_type") is not None)

        candidates = [(r, p) for r, p in candidates if has_provenance(p)] \
            if (expected_provider is not None or expected_model is not None) else candidates
        if expected_provider is not None:
            candidates = [(r, p) for r, p in candidates
                          if p.get("provider") == expected_provider and p.get("invocation_type") == "real_llm"]
            checks["provider"] = bool(candidates)
            if not candidates:
                return IgorVerification("BLOCK", "provider provenance mismatch", checks)
            if expected_provider != "local":
                candidates = [(r, p) for r, p in candidates
                              if isinstance(p.get("response_ids"), list) and p["response_ids"]]
                if not candidates:
                    return IgorVerification("BLOCK", "real LLM response ids missing", checks)
                checks["response_ids"] = True
        if expected_model is not None:
            candidates = [(r, p) for r, p in candidates if p.get("model") == expected_model]
            checks["model"] = bool(candidates)
            if not candidates:
                return IgorVerification("BLOCK", "model provenance mismatch", checks)

        checks["evidence"] = True
        evidence_ids = tuple(r.get("id") for r, _ in members if r.get("id"))
        return IgorVerification("VERIFIED", "independent verification passed", checks, evidence_ids)
