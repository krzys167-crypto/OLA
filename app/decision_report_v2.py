"""ADR-001 stage 1: bindings, not an execution attestation.

The legacy snapshot is opaque. Its verdicts never grant assurance. This module
cannot issue ATTESTED or VERIFIED; that requires the independent receipt path.
Encoding is Python sorted JSON, explicitly NOT RFC 8785 Evidence-Stream JCS.
"""
import hashlib
import json
import re

SCHEMA = "ola.decision-report.v2"
ENCODING = "ola.sorted-json.v1"
DOMAIN = b"OLA/decision-report/v2\x00"
BINDINGS = {"source_sha": 40, "policy_digest": 64, "evidence_root": 64,
            "human_approval_digest": 64}
REASON = "independent verifier receipt not implemented; bindings are claims"


def _encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _digest(body):
    return hashlib.sha256(DOMAIN + _encode(body)).hexdigest()


def build_decision_report_v2(*, legacy_report, source_sha=None,
                             policy_digest=None, evidence_root=None,
                             human_approval_digest=None):
    """Snapshot legacy data and explicit bindings without promoting trust."""
    if not isinstance(legacy_report, dict) or legacy_report.get("schema") != "ola.decision-report.v1":
        raise ValueError("expected legacy decision-report.v1")
    bindings = dict(source_sha=source_sha, policy_digest=policy_digest,
                    evidence_root=evidence_root,
                    human_approval_digest=human_approval_digest)
    for name, width in BINDINGS.items():
        value = bindings[name]
        if value is not None and (not isinstance(value, str) or
                                  re.fullmatch(r"[0-9a-f]{%d}" % width, value) is None):
            raise ValueError("invalid " + name)
    body = {"schema": SCHEMA, "encoding": ENCODING,
            "bindings": bindings,
            "evidence_scope": "legacy-report-input-chain-before-decision-candidate",
            "legacy_report": json.loads(_encode(legacy_report)),
            "assurance": {"status": "UNKNOWN", "reason": REASON},
            "production_eligible": False}
    body["report_sha256"] = _digest(body)
    return body


def inspect_decision_report_v2(report):
    """Check local report integrity. No key, anchor or execution authentication."""
    blocked = {"integrity": "BLOCKED", "assurance": "BLOCKED",
               "production_eligible": False}
    try:
        if not isinstance(report, dict):
            return blocked
        expected = build_decision_report_v2(
            legacy_report=report["legacy_report"], **report["bindings"])
        # Exact reconstruction rejects unknown fields, changed semantics, claims
        # of assurance and resealed forged promotions, as well as stale hashes.
        if _encode(expected) != _encode(report):
            return blocked
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
        return blocked
    return {"integrity": "LOCAL", "assurance": "UNKNOWN",
            "production_eligible": False}
