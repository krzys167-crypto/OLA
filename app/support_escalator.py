"""Support-to-engineering escalation template on OLA's existing NINA DAG.

Stage 1 is read-only: Intercom read -> parallel isolated repro and code lookup ->
evidence-bound draft -> independent IGOR. Stage 2 external mutations are a
separate explicitly authorized, idempotency-keyed handoff. No automatic Jira
issue for a case that could not be reproduced.
"""
from hashlib import sha256
from urllib.parse import urlsplit
import json
import os
import re

from .workflow_engine import WorkflowEngine, WorkflowPlanError, validate_plan


class EscalationBlocked(WorkflowPlanError):
    pass


def _str(value, field, limit=300):
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise EscalationBlocked("invalid " + field)
    if any(ord(c) < 32 and c not in "\t\n" for c in value):
        raise EscalationBlocked("control characters in " + field)
    return value.strip()


def _https(url, kind):
    if not isinstance(url, str) or len(url) > 450 or any(
            ord(c) < 33 or c in "()<>{}[]" for c in url):
        return False
    try:
        p = urlsplit(url)
        host = (p.hostname or "").lower()
    except ValueError:
        return False
    if p.scheme != "https" or p.username or p.password or not p.path:
        return False
    if kind == "intercom":
        return host in {"app.intercom.com", "app.intercom.io"} and "/conversation/" in p.path
    if kind == "github":
        return host == "github.com" and "/blob/" in p.path
    if kind == "jira":
        return host.endswith(".atlassian.net") and "/browse/" in p.path
    return False


def _safe_markdown(value):
    """Escape untrusted text, never allowing rendered Markdown links or images."""
    value = value.replace("\n", " ")
    # Escape existing backslashes first; added escapes must not be doubled.
    for char in ("\\", "`", "*", "_", "[", "]", "<", ">", "!"):
        value = value.replace(char, "\\" + char)
    return value

def _conversation(raw, conversation_id):
    if not isinstance(raw, dict) or raw.get("id") != conversation_id:
        raise EscalationBlocked("conversation ID mismatch")
    url = raw.get("url")
    if (not _https(url, "intercom")
            or urlsplit(url).path.rstrip("/").rsplit("/", 1)[-1] != conversation_id):
        raise EscalationBlocked("missing authentic conversation permalink")
    customer = raw.get("customer")
    if not isinstance(customer, dict):
        raise EscalationBlocked("customer plan context missing")
    plan = _str(customer.get("plan_tier"), "plan tier", 80)
    subject = _str(raw.get("subject"), "conversation subject", 180)
    description = _str(raw.get("description"), "support report", 400)
    notes = _str(raw.get("support_notes"), "support notes", 280)
    env = raw.get("environment")
    if not isinstance(env, dict) or not 1 <= len(env) <= 8:
        raise EscalationBlocked("customer environment missing or unbounded")
    clean_env = {}
    for k, v in env.items():
        if not isinstance(k, str) or not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_-]{0,39}", k):
            raise EscalationBlocked("invalid environment field")
        clean_env[k] = _str(v, "environment value", 100)
    steps = raw.get("steps")
    if not isinstance(steps, list) or not 1 <= len(steps) <= 8:
        raise EscalationBlocked("reproduction steps missing")
    steps = [_str(x, "reproduction step", 240) for x in steps]
    attachments = raw.get("attachments", [])
    if not isinstance(attachments, list) or len(attachments) > 8:
        raise EscalationBlocked("invalid attachment manifest")
    safe_attachments = []
    for item in attachments:
        if not isinstance(item, dict) or item.get("kind") not in {"log", "screenshot"}:
            raise EscalationBlocked("unsupported attachment")
        digest = item.get("sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise EscalationBlocked("attachment digest missing")
        safe_attachments.append({"kind": item["kind"], "sha256": digest})
    # Do not ingest raw logs/attachments or personal identities into the event chain.
    return {"id": conversation_id, "url": url, "plan_tier": plan, "subject": subject,
            "description": description, "environment": clean_env, "steps": steps,
            "support_notes": notes, "attachments": safe_attachments}


def _repro(raw):
    if not isinstance(raw, dict) or not isinstance(raw.get("reproduced"), bool):
        raise EscalationBlocked("repro result missing explicit boolean")
    attempts = raw.get("attempts")
    if not isinstance(attempts, list) or not 1 <= len(attempts) <= 8:
        raise EscalationBlocked("list exact attempted repro commands or requests")
    attempts = [_str(x, "repro attempt", 280) for x in attempts]
    if not raw["reproduced"]:
        return {"reproduced": False, "attempts": attempts,
                "observed": _str(raw.get("observed"), "non-repro outcome", 200)}
    digest = raw.get("evidence_sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise EscalationBlocked("repro evidence digest absent")
    env = _str(raw.get("environment"), "isolated reproduction environment", 120)
    if not ("isolated" in env.lower() or "sandbox" in env.lower()):
        raise EscalationBlocked("reproduction must use an isolated environment")
    return {
        "reproduced": True, "attempts": attempts,
        "trigger": _str(raw.get("trigger"), "exact reproduction trigger", 320),
        "expected": _str(raw.get("expected"), "expected output", 160),
        "observed": _str(raw.get("observed"), "observed output", 160),
        "environment": env, "evidence_sha256": digest,
    }


def _code_search(raw, expected_commit):
    if not isinstance(raw, dict):
        raise EscalationBlocked("missing code search")
    component = _str(raw.get("component"), "suspected component", 160)
    if (component.startswith("/") or ".." in component.split("/")
            or not re.fullmatch(r"[A-Za-z0-9._/-]+", component)):
        raise EscalationBlocked("component must be a relative repository path")
    refs = raw.get("refs")
    if not isinstance(refs, list) or not 1 <= len(refs) <= 4:
        raise EscalationBlocked("code reference missing")
    safe_refs = []
    for ref in refs:
        if not isinstance(ref, dict) or not _https(ref.get("url"), "github"):
            raise EscalationBlocked("untrusted code reference")
        if _str(ref.get("path"), "code path", 160) != component:
            raise EscalationBlocked("component and reference path disagree")
        source = urlsplit(ref["url"])
        expected_path = ("/krzysztofcieciwa07-ship-it/OLA/blob/"
                         + expected_commit + "/" + component)
        if (expected_commit == "UNKNOWN" or source.path != expected_path
                or source.query):
            raise EscalationBlocked("code permalink source/revision/path mismatch")
        safe_refs.append({"path": component, "url": ref["url"]})
    return {"component": component, "refs": safe_refs}


def _draft(conversation, repro, code, correlation):
    if not repro["reproduced"]:
        return {"status": "CANNOT_REPRODUCE", "tried": repro["attempts"],
                "observed": repro["observed"], "conversation_url": conversation["url"]}
    description = "\n".join([
        "Source conversation: " + conversation["url"],
        "Plan tier: " + _safe_markdown(conversation["plan_tier"]),
        "Environment: " + ", ".join(f"{k}={_safe_markdown(v)}" for k, v in sorted(conversation["environment"].items())),
        "Support report: " + _safe_markdown(conversation["description"]),
        "Support notes: " + _safe_markdown(conversation["support_notes"]),
        "Customer steps:",
        *("- " + _safe_markdown(x) for x in conversation["steps"]),
        "Exact isolated reproduction attempts:",
        *("- " + _safe_markdown(x) for x in repro["attempts"]),
        "Trigger: " + _safe_markdown(repro["trigger"]),
        "Expected: " + _safe_markdown(repro["expected"]),
        "Observed: " + _safe_markdown(repro["observed"]),
        "Repro evidence SHA256: " + repro["evidence_sha256"],
        "Suspected component: " + code["component"],
        "Code reference: " + code["refs"][0]["url"],
        "Correlation ID: " + correlation,
    ])
    if len(description) > 4900:
        raise EscalationBlocked("Jira draft oversized")
    return {"status": "REPRODUCED", "summary": _safe_markdown(conversation["subject"]),
            "description": description, "suspected_component": code["component"],
            "severity_guess": "MEDIUM_UNCONFIRMED",
            "conversation_url": conversation["url"],
            "correlation_id": correlation}


def run_support_escalation(*, tenant_id, requester_id, conversation_id,
                           intercom_reader=None, repro_runner=None, code_searcher=None,
                           append=None, fetch_records=None):
    """Prepare a ticket only on verified reproduction, with zero external writes.

    Host-provided repro_runner is responsible for safe, sandboxed commands:
    no shell command from a support message is evaluated by this module.
    """
    tenant_id = _str(tenant_id, "tenant", 120)
    requester_id = _str(requester_id, "requester", 120)
    conversation_id = _str(conversation_id, "conversation ID", 120)
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,120}", conversation_id):
        raise EscalationBlocked("invalid conversation identifier")
    if not all(callable(x) for x in (intercom_reader, repro_runner, code_searcher)):
        raise EscalationBlocked("Intercom/repro/code connectors required")
    if not all(callable(x) for x in (append, fetch_records)):
        raise EscalationBlocked("evidence connectors required")
    correlation = "ola-support-escalation-" + sha256(
        (tenant_id + "|" + conversation_id).encode()).hexdigest()[:24]
    nodes = validate_plan({"nodes": [
        {"id": "intercom", "tool": "support.intercom.read", "task": "Fetch scoped customer issue", "needs": []},
        {"id": "repro", "tool": "support.repro.isolated", "task": "Attempt safe, exact reproduction", "needs": ["intercom"]},
        {"id": "search", "tool": "support.code.search", "task": "Find suspected source component", "needs": ["intercom"]},
        {"id": "draft", "tool": "support.jira.draft", "task": "Draft or clearly deny ticket", "needs": ["intercom", "repro", "search"]},
    ]}, allowed_tools={"support.intercom.read", "support.repro.isolated", "support.code.search", "support.jira.draft"})
    meta = {"mode": "REVIEWED_ESCALATION_DAG_TEMPLATE", "conversation_id": conversation_id,
            "correlation_id": correlation}
    commit = os.getenv("OLA_RUNTIME_COMMIT", "UNKNOWN")

    def execute(node, deps):
        if node.id == "intercom":
            return _conversation(intercom_reader(conversation_id), conversation_id)
        if node.id == "repro":
            return _repro(repro_runner(deps["intercom"]))
        if node.id == "search":
            return _code_search(code_searcher(deps["intercom"]), commit)
        if node.id == "draft":
            return _draft(deps["intercom"], deps["repro"], deps["search"], correlation)
        raise EscalationBlocked("unknown escalation capability")

    def record(event):
        saved = append(tenant_id, event["event"], {
            **event, "requester_id": requester_id, "planner": meta, "commit": commit})
        if not isinstance(saved, dict) or not saved.get("id"):
            raise EscalationBlocked("evidence append unconfirmed")

    result = WorkflowEngine(max_workers=2).run(nodes, execute, record)
    if result["status"] != "COMPLETED_UNVERIFIED":
        raise EscalationBlocked("DAG blocked: " + str(result["failed"]))
    from .igor_support_escalation import verify_escalation_records
    igor = verify_escalation_records(fetch_records(tenant_id), tenant_id=tenant_id,
        run_id=result["run_id"], conversation_id=conversation_id,
        expected_commit=commit if commit != "UNKNOWN" else None)
    if igor["status"] != "VERIFIED":
        raise EscalationBlocked("IGOR rejected escalation: " + igor["reason"])
    draft = result["results"]["draft"]
    common = {"run_id": result["run_id"], "correlation_id": correlation,
              "conversation_id": conversation_id, "tenant_id": tenant_id,
              "requester_id": requester_id, "source_commit": commit,
              "igor": igor, "human_gate": "NOT_APPROVED",
              "production_authorized": False, "verified": False}
    if draft["status"] == "CANNOT_REPRODUCE":
        return {**common, "status": "CANNOT_REPRODUCE", "tried": draft["tried"],
                "observed": draft["observed"], "jira_draft": None}
    return {**common, "status": "REPRODUCED_DRAFT_UNAPPROVED",
            "jira_draft": draft}


def publish_escalation(candidate, *, authorized=False, evidence_reader=None,
                       jira_create_or_get=None, slack_post_once=None,
                       intercom_note_once=None, intercom_mark_once=None):
    """Explicit host-authorized handoff. No automatic retries or silent rollback.

    *_once adapters MUST implement atomic provider-backed idempotency keyed by
    correlation ID; a naive read-then-create is not sufficient under concurrency.
    """
    if not isinstance(candidate, dict) or candidate.get("status") != "REPRODUCED_DRAFT_UNAPPROVED":
        raise EscalationBlocked("only reproduced ticket drafts may be escalated")
    if candidate.get("igor", {}).get("status") != "VERIFIED":
        raise EscalationBlocked("IGOR approval missing")
    if authorized is not True:
        raise EscalationBlocked("external authorization required")
    if not all(callable(x) for x in (
            evidence_reader, jira_create_or_get, slack_post_once,
            intercom_note_once, intercom_mark_once)):
        raise EscalationBlocked("fresh evidence + authorized Jira/Slack/Intercom write adapters required")
    commit = candidate.get("source_commit")
    if not isinstance(commit, str) or commit in ("", "UNKNOWN"):
        raise EscalationBlocked("source SHA missing for mutation approval")
    from .igor_support_escalation import verify_escalation_records
    records = evidence_reader(candidate["tenant_id"])
    fresh = verify_escalation_records(records,
        tenant_id=candidate["tenant_id"], run_id=candidate["run_id"],
        conversation_id=candidate["conversation_id"], expected_commit=commit)
    if (fresh.get("status") != "VERIFIED"
            or fresh.get("report_digest") != candidate["igor"].get("report_digest")
            or fresh.get("chain_tip") != candidate["igor"].get("chain_tip")):
        raise EscalationBlocked("fresh IGOR/source/chain evidence mismatch")
    run_events = [json.loads(row["payload_json"]) for row in records
                  if row["record_type"] == "task.completed"
                  and json.loads(row["payload_json"]).get("run_id") == candidate["run_id"]
                  and json.loads(row["payload_json"]).get("node_id") == "draft"]
    if len(run_events) != 1 or run_events[0]["output"] != candidate.get("jira_draft"):
        raise EscalationBlocked("Jira draft differs from immutable execution evidence")
    key = candidate["correlation_id"]
    draft = candidate["jira_draft"]
    if draft.get("status") != "REPRODUCED" or draft.get("correlation_id") != key:
        raise EscalationBlocked("draft correlation mismatch")
    completed = []
    try:
        jira = jira_create_or_get(key + ":jira", draft)
        if (not isinstance(jira, dict) or not re.fullmatch(
                r"[A-Z][A-Z0-9]+-[1-9][0-9]*", str(jira.get("key", "")))
                or not _https(jira.get("url"), "jira")
                or urlsplit(jira["url"]).path != "/browse/" + jira["key"]):
            raise EscalationBlocked("Jira did not confirm valid issue link")
        completed.append("jira")
        message = {"conversation_url": draft["conversation_url"], "jira_url": jira["url"],
                   "severity_guess": draft["severity_guess"],
                   "correlation_id": key, "status": "ESCALATION_RECORDED"}
        notice = slack_post_once(key + ":slack", message)
        if not isinstance(notice, dict) or not notice.get("id"):
            raise EscalationBlocked("Slack note receipt missing")
        completed.append("slack")
        note = intercom_note_once(key + ":note",
            {"conversation_id": candidate["conversation_id"],
             "jira_url": jira["url"], "correlation_id": key})
        if not isinstance(note, dict) or not note.get("id"):
            raise EscalationBlocked("Intercom note receipt missing")
        completed.append("note")
        state = intercom_mark_once(key + ":mark",
            {"conversation_id": candidate["conversation_id"],
             "jira_url": jira["url"], "status": "escalated"})
        if not isinstance(state, dict) or state.get("status") != "escalated":
            raise EscalationBlocked("Intercom escalation status not confirmed")
        completed.append("mark")
    except Exception as exc:
        raise EscalationBlocked(
            "partial external handoff requires reconciliation; completed="
            + ",".join(completed) + "; correlation=" + key
            + "; error=" + type(exc).__name__) from exc
    return {"status": "ESCALATED_RECORDED_UNATTESTED", "jira": jira,
            "conversation_id": candidate["conversation_id"], "correlation_id": key,
            "completed_stages": completed,
            "trust_scope": "ADAPTER_RECEIPTS_NOT_INDEPENDENT_EXTERNAL_ATTESTATION"}
