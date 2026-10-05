"""Agent Firewall: a deterministic ALLOW / REVIEW / BLOCK decision in front of an agent action, recorded in
the tenant evidence chain, with single-use, action-bound human approval.

This is the executable core of the OLA Agent Firewall contract (README v0.2, "E2E Definition of Done") built
on OLA's own primitives (tenant chain, tenant API key). It is NOT the v0.3 demo engine: that engine kept its
evidence in memory, trusted a client-supplied `contains_secret` flag, never loaded its YAML policy and answered
ALLOW to anything it did not know. Here the opposite holds.

Flow (all state is derived from the tenant chain; nothing is trusted from a stored verdict)
    authorize(...)  -> decision (+ `firewall.decision` record). No record -> no decision (HTTP 503).
    approve(...)    -> only for REVIEW; `firewall.approval`; approver != agent; reason required; expires;
                       bound to the action digest; one approval per request.
    consume(...)    -> the caller must present the SAME action again; returns permit=True only if the decision
                       is ALLOW, or REVIEW with a live approval, and no permit was claimed before. Every call
                       appends `firewall.execution`; `permitted: true` there is a CLAIM and the lowest chain seq
                       among claims is the one permit - later claims are denied in the response (their record
                       still says claimed, which is why the view counts claims, not trust).
    state(...)      -> read-only view derived from the chain.

Fail-closed rules (each has a test)
* Unknown action family -> REVIEW. Unknown/missing environment -> treated as production.
* Malformed input -> HTTP 400 (no decision exists, so nothing can be permitted).
* A secret found by the server's own scan, or flagged by the caller, can only raise risk or BLOCK; the flag can
  never lower it.
* Evidence cannot be written -> no decision is returned.
* The tenant chain must verify before any decision or state is produced.
* Evidence stores SHA-256 digests of the action and of the command/payload, never their text.

HONEST LIMITS
* Identity. By default (`OLA_FIREWALL_AGENT_AUTH` off) `agent_id` and `approver_id` are asserted by the holder of
  the tenant API key and the approver != agent rule only stops the same string doing both. With signed requests
  (app/identity.py: Ed25519 keys enrolled in the chain, `OLA_FIREWALL_AGENT_AUTH=required`) a principal is a key, an
  approver key can never be an agent key, and a decision that was not made by a verified agent can be neither
  approved nor consumed. That is still not an identity provider: it does not prove an approver is a person, and the
  enrolment token / tenant API key remain the root of trust (see app/identity.py).
* The firewall decides; it does not execute and cannot stop a caller that skips it. Enforcement requires that
  the executor only acts on a `consume` permit.
* The risk model is a transparent additive heuristic, not a measured one. The rule table is versioned and
  digest-pinned by a test; changing a rule without bumping POLICY_VERSION fails that test.
* State is rebuilt by scanning the tenant chain: correct, O(records). Index it before heavy use.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from . import identity
from . import pipeline_bridge as pb
from .hashchain import canonical_json, verify_chain

SCHEMA = "ola.firewall/1"
POLICY_VERSION = "1.0"
DECISION_TYPE, APPROVAL_TYPE, EXECUTION_TYPE = "firewall.decision", "firewall.approval", "firewall.execution"
ALLOW, REVIEW, BLOCK = "ALLOW", "REVIEW", "BLOCK"

# Rule table: ORDER MATTERS, first match wins. Pinned by tests/test_firewall.py (digest) - bump POLICY_VERSION.
RULES: Tuple[Dict[str, str], ...] = (
    {"id": "PRODUCTION-DELETE-BLOCK", "effect": BLOCK, "when": "environment == production AND family == delete"},
    {"id": "DLP-SECRET-EXFIL-BLOCK", "effect": BLOCK,
     "when": "secret detected AND family in [external_send, file_upload, transfer, mcp_tool, browser]"},
    {"id": "HIGH-RISK-HUMAN-APPROVAL", "effect": REVIEW,
     "when": "risk >= 70 OR (family == transfer AND value >= 1000) OR family unknown"},
    {"id": "STANDARD-ACTION", "effect": ALLOW, "when": "otherwise"},
)
RISK_WEIGHTS: Dict[str, int] = {"base": 10, "high_impact_family": 45, "production": 30, "transfer": 40,
                                "value_ge_5000": 20, "external_side_effect": 20, "secret": 35,
                                "unknown_family": 40}
HIGH_IMPACT = frozenset({"delete", "code_exec", "shell", "credential_use", "external_send", "file_upload"})
EXTERNAL = frozenset({"external_send", "file_upload", "transfer", "mcp_tool", "browser"})
KNOWN_FAMILIES = HIGH_IMPACT | {"read", "write", "query", "transfer", "mcp_tool", "browser", "computer"}
ENVIRONMENTS = {"production": "production", "prod": "production", "staging": "staging", "stage": "staging",
                "development": "development", "dev": "development", "test": "test"}
RISK_THRESHOLD, TRANSFER_REVIEW_VALUE = 70, 1000


def policy_digest() -> str:
    return hashlib.sha256(canonical_json({"version": POLICY_VERSION, "rules": list(RULES), "weights": RISK_WEIGHTS,
                                          "high_impact": sorted(HIGH_IMPACT), "external": sorted(EXTERNAL),
                                          "known": sorted(KNOWN_FAMILIES), "threshold": RISK_THRESHOLD,
                                          "transfer_review": TRANSFER_REVIEW_VALUE}).encode()).hexdigest()


class FirewallError(ValueError):
    """Malformed request (HTTP 400)."""


class FirewallNotFound(LookupError):
    """No such request for this tenant (HTTP 404)."""


class FirewallConflict(RuntimeError):
    """The request is not in a state that allows this operation (HTTP 409)."""


class FirewallUnavailable(RuntimeError):
    """Evidence could not be written or read: no decision may be issued (HTTP 503)."""


_ID = re.compile(r"^[A-Za-z0-9_.:@-]{1,64}$")
_SECRETS = tuple(re.compile(p) for p in (
    r"AKIA[0-9A-Z]{16}",
    r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----",
    r"gh[pousr]_[A-Za-z0-9]{30,}",
    r"sk-[A-Za-z0-9_-]{20,}",
    r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
    r"(?i)\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\b\s*[=:]\s*\S{6,}",
    r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{16,}",
))


def _sha(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _strings(value: Any, depth: int = 0):
    if depth > 6:
        return
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield str(k)
            yield from _strings(v, depth + 1)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _strings(v, depth + 1)


def has_secret(value: Any) -> bool:
    return any(p.search(s) for s in _strings(value) for p in _SECRETS)


# ------------------------------------------------------------------ normalisation
def normalize(agent_id: Any, action: Any, context: Any = None) -> Dict[str, Any]:
    if not isinstance(agent_id, str) or not _ID.match(agent_id):
        raise FirewallError("agent_id must match [A-Za-z0-9_.:@-]{1,64}")
    if not isinstance(action, dict):
        raise FirewallError("action must be an object")
    if context is not None and not isinstance(context, dict):
        raise FirewallError("context must be an object")
    context = context or {}
    atype = action.get("type")
    if not isinstance(atype, str) or not atype.strip() or len(atype) > 64:
        raise FirewallError("action.type is required")
    atype = atype.strip().lower()
    value = action.get("value", 0)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value != value or value < 0 \
            or value > 1e15:
        raise FirewallError("action.value must be a non-negative number")
    target = action.get("target", "")
    if not isinstance(target, str) or len(target) > 256:
        raise FirewallError("action.target must be a string of at most 256 characters")
    raw_env = context.get("environment", action.get("environment"))
    if raw_env is not None and not isinstance(raw_env, str):
        raise FirewallError("environment must be a string")
    env = ENVIRONMENTS.get((raw_env or "").strip().lower())
    return {"agent_id": agent_id, "type": atype, "family": atype.split(".")[0], "target": target,
            "value": float(value), "environment": env or "production", "environment_assumed": env is None,
            "flag_secret": action.get("contains_secret") is True or context.get("contains_secret") is True,
            "external_side_effect": action.get("external_side_effect") is True,
            "scan": {k: action.get(k) for k in ("command", "payload", "args", "arguments", "body", "content", "url")
                     if k in action}}


def action_digest(n: Dict[str, Any]) -> str:
    """Identity of the action: what must be identical at approval and at execution."""
    return _sha({"agent_id": n["agent_id"], "type": n["type"], "target": n["target"], "value": n["value"],
                 "environment": n["environment"], "scan_sha256": _sha(n["scan"])})


# ------------------------------------------------------------------ the decision (pure, deterministic)
def evaluate(n: Dict[str, Any]) -> Dict[str, Any]:
    fam, env = n["family"], n["environment"]
    w, risk, reasons = RISK_WEIGHTS, RISK_WEIGHTS["base"], []
    secret = n["flag_secret"] or has_secret(n["scan"])
    unknown = fam not in KNOWN_FAMILIES
    if fam in HIGH_IMPACT:
        risk += w["high_impact_family"]; reasons.append("high-impact capability")
    if unknown:
        risk += w["unknown_family"]; reasons.append("unknown action family (not permitted by default)")
    if env == "production":
        risk += w["production"]; reasons.append("production target" + (" (environment not stated)" if n["environment_assumed"] else ""))
    if fam == "transfer":
        risk += w["transfer"]; reasons.append("financial transaction")
    if n["value"] >= 5000:
        risk += w["value_ge_5000"]; reasons.append("value at or above 5000")
    if n["external_side_effect"] and fam in {"mcp_tool", "browser", "computer"}:
        risk += w["external_side_effect"]; reasons.append("external side effect")
    if secret:
        risk += w["secret"]; reasons.append("secret-bearing payload")
    risk = min(100, risk)
    if env == "production" and fam == "delete":
        decision, rule = BLOCK, "PRODUCTION-DELETE-BLOCK"
    elif secret and fam in EXTERNAL:
        decision, rule = BLOCK, "DLP-SECRET-EXFIL-BLOCK"
    elif risk >= RISK_THRESHOLD or (fam == "transfer" and n["value"] >= TRANSFER_REVIEW_VALUE) or unknown:
        decision, rule = REVIEW, "HIGH-RISK-HUMAN-APPROVAL"
    else:
        decision, rule = ALLOW, "STANDARD-ACTION"
    return {"decision": decision, "risk_score": risk, "policy_id": rule, "reasons": reasons, "secret_detected": secret}


# ------------------------------------------------------------------ chain-derived state
def _events(tenant_id: str) -> Tuple[List[dict], Dict[str, List[Tuple[dict, dict]]]]:
    try:
        chain = pb.load_chain(tenant_id)
    except Exception as exc:                                         # noqa: BLE001 - fail closed
        raise FirewallUnavailable(f"evidence could not be read ({type(exc).__name__})") from exc
    ok, why = verify_chain(chain)
    if not ok:                                   # state derived from a chain that does not verify is not state
        raise FirewallUnavailable(f"the tenant evidence chain does not verify ({why})")
    by_req: Dict[str, List[Tuple[dict, dict]]] = {}
    for rec in chain:
        if rec["record_type"] in (DECISION_TYPE, APPROVAL_TYPE, EXECUTION_TYPE):
            try:
                p = json.loads(rec["payload_json"])
            except ValueError:
                continue
            if isinstance(p, dict) and isinstance(p.get("request_id"), str) and p.get("schema") == SCHEMA:
                by_req.setdefault(p["request_id"], []).append((rec, p))
    return chain, by_req


def _append(tenant_id: str, rtype: str, payload: dict) -> dict:
    try:
        return pb.append_evidence(tenant_id, rtype, payload)
    except Exception as exc:                                         # noqa: BLE001 - no record, no decision
        raise FirewallUnavailable(f"the decision could not be recorded ({type(exc).__name__})") from exc


def _authenticate(chain: List[dict], tenant_id: str, purpose: str, principal_id: str, role: str, subject: str,
                  auth: Any) -> Optional[Dict[str, Any]]:
    """None only when the request is unsigned AND signatures are not required. A signature that is supplied is
    always verified: a bad one is denied, never ignored."""
    if auth is None and identity.auth_mode() == "off":
        return None
    return identity.verify(chain, tenant_id, purpose, principal_id, role, subject, auth)


def _auth_fields(proof: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if proof is None:
        return {"identity": "asserted", "auth": None}
    return {"identity": "verified", "auth": {k: proof[k] for k in ("principal_id", "role", "key_sha256", "nonce", "ts",
                                                                   "signature_sha256")}}


def authorize_subject(agent_id: Any, action: Any, context: Any = None) -> str:
    """What an agent signs for authorize(): the digest of the action it wants to take."""
    return action_digest(normalize(agent_id, action, context))


def consume_subject(request_id: str, agent_id: Any, action: Any, context: Any = None) -> str:
    return _sha({"request_id": request_id, "action_digest": action_digest(normalize(agent_id, action, context))})


def approve_subject(request_id: str, reason: str) -> str:
    return _sha({"request_id": request_id, "reason_sha256": hashlib.sha256(reason.encode("utf-8")).hexdigest()})


def _ttl() -> int:
    try:
        return pb._int_env("OLA_FIREWALL_APPROVAL_TTL_S", 900)
    except pb.PipelineNotConfigured as exc:
        raise FirewallUnavailable(str(exc)) from exc


def _now() -> float:
    return time.time()


def _view(request_id: str, events: List[Tuple[dict, dict]], now: float, ttl: int) -> Dict[str, Any]:
    decisions = [(r, p) for r, p in events if r["record_type"] == DECISION_TYPE]
    if len(decisions) != 1:
        raise FirewallNotFound("no such request")
    drec, d = decisions[0]
    approvals = [(r, p) for r, p in events if r["record_type"] == APPROVAL_TYPE and p.get("decision_seq") == drec["seq"]]
    executions = sorted((r["seq"], p) for r, p in events if r["record_type"] == EXECUTION_TYPE)
    approval = approvals[0][1] if approvals else None
    live = bool(approval) and now <= float(approval["approved_at"]) + ttl
    first_exec = next((s for s, p in executions if p.get("permitted") is True), None)
    if d["decision"] == BLOCK:
        phase = "BLOCKED"
    elif first_exec is not None:
        phase = "EXECUTED"
    elif d["decision"] == ALLOW:
        phase = "PERMITTED"
    elif approval is None:
        phase = "AWAITING_APPROVAL"
    else:
        phase = "PERMITTED" if live else "APPROVAL_EXPIRED"
    return {"request_id": request_id, "decision": d["decision"], "risk_score": d["risk_score"],
            "policy_id": d["policy_id"], "policy_version": d["policy_version"], "policy_sha256": d["policy_sha256"],
            "reasons": d["reasons"], "agent_id": d["agent_id"], "environment": d["environment"],
            "action_digest": d["action_digest"], "decision_seq": drec["seq"], "phase": phase,
            "identity": d.get("identity", "asserted"),
            "agent_key_sha256": (d.get("auth") or {}).get("key_sha256"),
            "approval": None if approval is None else {"approver_id": approval["approver_id"],
                                                       "identity": approval.get("identity", "asserted"),
                                                       "reason_sha256": approval["reason_sha256"],
                                                       "approved_at": approval["approved_at"], "live": live},
            "executions": len(executions)}


def authorize(tenant_id: str, agent_id: Any, action: Any, context: Any = None, auth: Any = None) -> Dict[str, Any]:
    n = normalize(agent_id, action, context)
    ev = evaluate(n)
    chain, _ = _events(tenant_id)                # refuses (503) when the tenant chain is unreadable or broken
    proof = _authenticate(chain, tenant_id, "firewall.authorize", n["agent_id"], "agent", action_digest(n), auth)
    request_id = "req_" + uuid.uuid4().hex[:20]
    payload = {"schema": SCHEMA, "request_id": request_id, "agent_id": n["agent_id"], "action_type": n["type"],
               "family": n["family"], "target": n["target"], "value": n["value"], "environment": n["environment"],
               "environment_assumed": n["environment_assumed"], "action_digest": action_digest(n),
               "decision": ev["decision"], "risk_score": ev["risk_score"], "policy_id": ev["policy_id"],
               "policy_version": POLICY_VERSION, "policy_sha256": policy_digest(), "reasons": ev["reasons"],
               "secret_detected": ev["secret_detected"], "created_at": _now(), **_auth_fields(proof)}
    rec = _append(tenant_id, DECISION_TYPE, payload)
    return {"request_id": request_id, "decision": ev["decision"], "risk_score": ev["risk_score"],
            "policy_id": ev["policy_id"], "policy_version": POLICY_VERSION, "reasons": ev["reasons"],
            "approval_required": ev["decision"] == REVIEW, "evidence_seq": rec["seq"],
            "action_digest": payload["action_digest"], "identity": payload["identity"],
            "permit": False}                                    # a permit exists only after consume()


def state(tenant_id: str, request_id: str) -> Dict[str, Any]:
    _, by_req = _events(tenant_id)
    if request_id not in by_req:
        raise FirewallNotFound("no such request")
    return _view(request_id, by_req[request_id], _now(), _ttl())


def approve(tenant_id: str, request_id: str, approver_id: Any, reason: Any, auth: Any = None) -> Dict[str, Any]:
    if not isinstance(approver_id, str) or not _ID.match(approver_id):
        raise FirewallError("approver_id must match [A-Za-z0-9_.:@-]{1,64}")
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 1000:
        raise FirewallError("reason is required (1-1000 characters)")
    chain, by_req = _events(tenant_id)
    proof = _authenticate(chain, tenant_id, "firewall.approve", approver_id, "approver",
                          approve_subject(str(request_id), reason), auth)
    if request_id not in by_req:
        raise FirewallNotFound("no such request")
    v = _view(request_id, by_req[request_id], _now(), _ttl())
    if v["decision"] != REVIEW:
        raise FirewallConflict(f"only REVIEW decisions can be approved (this one is {v['decision']})")
    if v["approval"] is not None:
        raise FirewallConflict("this request already has an approval")
    if approver_id == v["agent_id"]:
        raise FirewallConflict("an agent cannot approve its own action")
    if identity.auth_mode() == "required" and v["identity"] != "verified":
        raise FirewallConflict("this decision was not made by a verified agent, so it cannot be approved")
    if proof is not None and v["agent_key_sha256"] and proof["key_sha256"] == v["agent_key_sha256"]:
        raise FirewallConflict("an agent cannot approve its own action (same key)")
    rec = _append(tenant_id, APPROVAL_TYPE, {
        "schema": SCHEMA, "request_id": request_id, "decision_seq": v["decision_seq"],
        "action_digest": v["action_digest"], "approver_id": approver_id,
        "reason_sha256": hashlib.sha256(reason.encode("utf-8")).hexdigest(), "approved_at": _now(),
        **_auth_fields(proof)})
    # one approval per decision: the lowest seq wins a race
    _, again = _events(tenant_id)
    mine = [r["seq"] for r, p in again[request_id] if r["record_type"] == APPROVAL_TYPE
            and p.get("decision_seq") == v["decision_seq"]]
    if min(mine) != rec["seq"]:
        raise FirewallConflict("another approval for this request was recorded first")
    return {"request_id": request_id, "status": "APPROVED", "approval_seq": rec["seq"],
            "expires_in_s": _ttl()}


def consume(tenant_id: str, request_id: str, agent_id: Any, action: Any, context: Any = None,
            auth: Any = None) -> Dict[str, Any]:
    """The executor calls this immediately before acting. permit=True at most once per request."""
    n = normalize(agent_id, action, context)
    chain, by_req = _events(tenant_id)
    proof = _authenticate(chain, tenant_id, "firewall.consume", n["agent_id"], "agent",
                          _sha({"request_id": request_id, "action_digest": action_digest(n)}), auth)
    if request_id not in by_req:
        raise FirewallNotFound("no such request")
    v = _view(request_id, by_req[request_id], _now(), _ttl())
    reason = ""
    if action_digest(n) != v["action_digest"]:
        reason = "the action differs from the one that was decided"
    elif identity.auth_mode() == "required" and v["identity"] != "verified":
        reason = "the decision was not made by a verified agent"
    elif v["phase"] != "PERMITTED":
        reason = {"BLOCKED": "the action was blocked", "AWAITING_APPROVAL": "human approval is still required",
                  "APPROVAL_EXPIRED": "the approval has expired", "EXECUTED": "the permit was already used"
                  }.get(v["phase"], "not permitted")
    permitted = reason == ""
    rec = _append(tenant_id, EXECUTION_TYPE, {
        "schema": SCHEMA, "request_id": request_id, "decision_seq": v["decision_seq"],
        "action_digest": action_digest(n), "permitted": permitted, "reason": reason, "at": _now(),
        **_auth_fields(proof)})
    if permitted:                                                     # the lowest-seq permitted record wins a race
        _, again = _events(tenant_id)
        winners = sorted(r["seq"] for r, p in again[request_id]
                         if r["record_type"] == EXECUTION_TYPE and p.get("permitted") is True)
        if winners[0] != rec["seq"]:
            permitted, reason = False, "the permit was already used"
    return {"request_id": request_id, "permit": permitted, "reason": reason, "evidence_seq": rec["seq"]}
