"""Independent support escalation replay verifier: never invokes repro or Jira.

VERIFIED means captured local evidence is internally consistent, NOT that a
real Intercom identity, Jira provider, or sandbox command is independently
attested. All external-write receipts are deliberately outside this verifier.
"""
import hashlib
import json
import re
from urllib.parse import urlsplit

from .igor_workflow import verify_dag_records


def _block(reason):
    return {"status": "BLOCK", "reason": reason,
            "trust_scope": "LOCAL_HASH_CHAIN_AND_CAPTURED_REPRO_NOT_EXTERNAL_ATTESTATION"}


def _permalink(url, provider):
    if not isinstance(url, str) or len(url) > 450:
        return False
    if any(ord(char) < 33 or char in "()<>[]{}" for char in url):
        return False
    try:
        p = urlsplit(url)
    except ValueError:
        return False
    if p.scheme != "https" or p.username or p.password or not p.path:
        return False
    host = (p.hostname or "").lower()
    if provider == "intercom":
        return host in {"app.intercom.com", "app.intercom.io"} and "/conversation/" in p.path
    if provider == "github":
        return host == "github.com" and "/blob/" in p.path
    return False


def verify_escalation_records(records, *, tenant_id, run_id, conversation_id,
                              expected_commit=None):
    base = verify_dag_records(records, tenant_id=tenant_id, run_id=run_id,
                              expected_commit=expected_commit)
    if base["status"] != "VERIFIED":
        return _block("DAG integrity: " + base["reason"])
    try:
        events = [json.loads(row["payload_json"]) for row in records
                  if json.loads(row["payload_json"]).get("run_id") == run_id
                  and row["record_type"].startswith(("workflow.", "task."))]
        plan = events[0]
        expected = [
            ("intercom", "support.intercom.read", []),
            ("repro", "support.repro.isolated", ["intercom"]),
            ("search", "support.code.search", ["intercom"]),
            ("draft", "support.jira.draft", ["intercom", "repro", "search"]),
        ]
        if (plan.get("event") != "workflow.planned"
                or [(x["id"], x["tool"], x["needs"]) for x in plan["nodes"]] != expected
                or plan.get("planner", {}).get("mode") != "REVIEWED_ESCALATION_DAG_TEMPLATE"
                or plan["planner"].get("conversation_id") != conversation_id):
            return _block("unknown escalation DAG topology or conversation")
        starts = {event["node_id"]: event for event in events
                  if event.get("event") == "task.completed"}
        if set(starts) != {"intercom", "repro", "search", "draft"}:
            return _block("incomplete escalation events")
        c, r, s, d = (starts[n]["output"] for n in ("intercom", "repro", "search", "draft"))
        if (c.get("id") != conversation_id
                or not _permalink(c.get("url"), "intercom")
                or urlsplit(c["url"]).path.rstrip("/").rsplit("/", 1)[-1] != conversation_id):
            return _block("invalid Intercom conversation identity")
        if not isinstance(c.get("steps"), list) or not c["steps"]:
            return _block("missing customer reproduction steps")
        if not isinstance(r.get("reproduced"), bool) or not isinstance(r.get("attempts"), list) or not r["attempts"]:
            return _block("missing reproduction attempts")
        if (not isinstance(s.get("component"), str) or not s["component"]
                or not isinstance(s.get("refs"), list) or not s["refs"]):
            return _block("missing suspected component evidence")
        for ref in s["refs"]:
            if ref.get("path") != s["component"] or not _permalink(ref.get("url"), "github"):
                return _block("missing component source link")
            link = urlsplit(ref["url"])
            expected_path = ("/krzysztofcieciwa07-ship-it/OLA/blob/"
                             + str(plan.get("commit")) + "/" + s["component"])
            if (plan.get("commit") in (None, "UNKNOWN")
                    or link.path != expected_path or link.query):
                return _block("component permalink does not bind source SHA")
        left, right = starts["repro"], starts["search"]
        overlap = (min(left["worker_finished_ns"], right["worker_finished_ns"])
                   - max(left["worker_started_ns"], right["worker_started_ns"]))
        # Workers are submitted independently to the same thread pool.
        # Very short calls may finish without positive measured overlap; do
        # not claim physical overlap or block a valid instant response.
        measured_overlap_ns = max(0, overlap)
        if r["reproduced"]:
            if (not isinstance(r.get("trigger"), str) or not r["trigger"]
                    or not re.fullmatch(r"[0-9a-f]{64}", str(r.get("evidence_sha256", "")))):
                return _block("no exact reproduced trigger or evidence")
            if (d.get("status") != "REPRODUCED" or d.get("conversation_url") != c["url"]
                    or d.get("suspected_component") != s["component"]
                    or not isinstance(d.get("description"), str)
                    or not isinstance(d.get("summary"), str)):
                return _block("inconsistent Jira draft")
            for evidence in [c["url"], r["trigger"], r["evidence_sha256"],
                             r["expected"], r["observed"], s["component"], s["refs"][0]["url"]]:
                if evidence not in d["description"]:
                    return _block("draft omits a required source evidence element")
            if not isinstance(d.get("correlation_id"), str) or d["correlation_id"] != plan["planner"].get("correlation_id"):
                return _block("correlation ID mismatch")
        else:
            if d.get("status") != "CANNOT_REPRODUCE" or d.get("tried") != r["attempts"]:
                return _block("unreproduced case wrongly escalated")
            if d.get("summary") or d.get("correlation_id"):
                return _block("Jira ticket claimed without reproduction")
        return {**base, "status": "VERIFIED",
                "reason": "captured support DAG, reproduction and code source links consistent",
                "parallel_overlap_ns": measured_overlap_ns,
                "observed_parallel_execution": measured_overlap_ns > 0,
                "reproduced": r["reproduced"],
                "conversation_id": conversation_id,
                "trust_scope": "LOCAL_CHAIN_CAPTURED_REPRO_AND_LINKS_NOT_EXTERNAL_PROVIDER_ATTESTATION"}
    except (TypeError, KeyError, ValueError, AttributeError, IndexError):
        return _block("malformed escalation evidence")
