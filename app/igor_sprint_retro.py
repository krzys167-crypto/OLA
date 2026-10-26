"""Independent IGOR checker for retrospective evidence captured by NINA DAG.

Reads only recorded evidence, never imports the executor, summarizer, or source
adapters. A VERIFIED verdict covers captured links/integrity, not factual truth
of messages or independent external provider attestation.
"""
import hashlib
import json
import re
from datetime import datetime
from urllib.parse import urlsplit
from .igor_workflow import verify_dag_records


def _block(reason):
    return {"status": "BLOCK", "reason": reason, "trust_scope": "CAPTURED_REFERENCES_ONLY"}


def _literal(value):
    """Independent Markdown text canonicalization, without importing NINA renderer."""
    value = value.replace("\n", " ")
    for char in ("\\", "`", "*", "_", "[", "]", "<", ">", "!"):
        value = value.replace(char, "\\" + char)
    return value


def _expected_document(cycle_id, summary):
    parts = ["# Sprint retro — " + _literal(cycle_id), "",
             "Draft for human review. Links are source references; no automatic publishing.", ""]
    for key, title in (("went_well", "Went well"), ("dragged", "Dragged"),
                       ("try_next_sprint", "Try next sprint")):
        parts.extend(["## " + title, ""])
        for item in summary[key]:
            refs = " ".join(f"[source {i+1}]({url})" for i, url in enumerate(item["refs"]))
            parts.append("- " + _literal(item["text"]) + " — " + refs)
        parts.append("")
    parts.extend(["## Proposed single process change", "",
                  _literal(summary["process_change"]), "",
                  "Estimated confidence: " + str(round(summary["confidence"] * 100))
                  + "% (qualitative estimate, not measured adoption).", ""])
    return "\n".join(parts)


def verify_sprint_retro_records(records, *, tenant_id, run_id, cycle_id,
                                expected_commit=None):
    base = verify_dag_records(records, tenant_id=tenant_id, run_id=run_id,
                              expected_commit=expected_commit)
    if base["status"] != "VERIFIED":
        return _block("DAG evidence: " + base["reason"])
    try:
        events = [json.loads(row["payload_json"]) for row in records
                  if json.loads(row["payload_json"]).get("run_id") == run_id
                  and row["record_type"].startswith(("workflow.", "task."))]
        graph = events[0]["nodes"]
        expected = [
            ("linear", "retro.linear.read", []),
            ("slack", "retro.slack.read", []),
            ("synthesis", "retro.synthesize", ["linear", "slack"]),
            ("document", "retro.render", ["synthesis"]),
        ]
        if len(graph) != 4 or [(n["id"], n["tool"], n["needs"]) for n in graph] != expected:
            return _block("retro DAG topology differs from reviewed template")
        outputs = {event["node_id"]: event["output"] for event in events
                   if event.get("event") == "task.completed"}
        if set(outputs) != {"linear", "slack", "synthesis", "document"}:
            return _block("retro source or output node missing")
        linear, slack = outputs["linear"], outputs["slack"]
        if linear.get("cycle_id") != cycle_id or linear.get("closed") is not True:
            return _block("sprint cycle not closed or wrong")
        tickets, messages = linear["tickets"], slack["messages"]
        planner = events[0]["planner"]
        if slack.get("channel_id") != planner.get("channel_id"):
            return _block("scoped Slack channel mismatch")
        lower = datetime.fromisoformat(planner["start"].replace("Z", "+00:00"))
        upper = datetime.fromisoformat(planner["end"].replace("Z", "+00:00"))
        if lower.tzinfo is None or upper.tzinfo is None or lower >= upper:
            return _block("invalid saved sprint window")
        for msg in messages:
            if not re.fullmatch(r"/archives/" + re.escape(planner["channel_id"]) + r"/p[0-9]+",
                                urlsplit(msg["url"]).path):
                return _block("Slack permalink channel differs from requested scope")
            timestamp = datetime.fromisoformat(msg["sent_at"].replace("Z", "+00:00"))
            if timestamp.tzinfo is None or not lower <= timestamp <= upper:
                return _block("source message outside saved sprint window")
        links = {ticket["url"] for ticket in tickets} | {msg["url"] for msg in messages}
        if not tickets or not messages or not links:
            return _block("missing source links")
        doc = outputs["document"]
        markdown, supplied_sha = doc["markdown"], doc["sha256"]
        if (not isinstance(markdown, str) or not markdown.startswith("# Sprint retro — ")
                or hashlib.sha256(markdown.encode()).hexdigest() != supplied_sha):
            return _block("document content digest mismatch")
        summary = outputs["synthesis"]
        if not isinstance(summary, dict):
            return _block("synthesis missing")
        headings = (("went_well", "Went well"), ("dragged", "Dragged"),
                    ("try_next_sprint", "Try next sprint"))
        for name, title in headings:
            bullets = summary.get(name)
            if not isinstance(bullets, list) or not 3 <= len(bullets) <= 5:
                return _block("missing 3-5 items per section")
            if markdown.count("## " + title) != 1:
                return _block("document heading missing")
            for bullet in bullets:
                refs = bullet.get("refs")
                if (not isinstance(refs, list) or not 1 <= len(refs) <= 3
                        or any(not isinstance(ref, str) or ref not in links for ref in refs)):
                    return _block("uncited or invented reference")
                for ref in refs:
                    if "](" + ref + ")" not in markdown:
                        return _block("source citation absent from document")
        if (not isinstance(summary.get("process_change"), str)
                or "## Proposed single process change" not in markdown
                or markdown.count("## Proposed single process change") != 1):
            return _block("single process change not recorded")
        confidence = summary.get("confidence")
        if (not isinstance(confidence, (int, float)) or isinstance(confidence, bool)
                or not 0 <= confidence <= 1):
            return _block("invalid document confidence")
        # An independently recomputed digest of tampered Markdown can be valid.
        # Verify the full semantic rendering against the recorded synthesis.
        if markdown != _expected_document(cycle_id, summary):
            return _block("document differs from recorded synthesis")
        beginnings = {event["node_id"]: event for event in events
                      if event.get("event") == "task.completed"}
        left, right = beginnings["linear"], beginnings["slack"]
        overlap = min(left["worker_finished_ns"], right["worker_finished_ns"]) - max(
                  left["worker_started_ns"], right["worker_started_ns"])
        # A successful parallel scheduler need not produce measurable time overlap
        # when the source callbacks complete nearly instantaneously.
        # Record overlap as telemetry, not an independent validity criterion.
        return {**base, "status": "VERIFIED",
                "reason": "captured retro DAG, sources, citations and document digest consistent",
                "document_sha256": supplied_sha,
                "source_ticket_count": len(tickets), "source_message_count": len(messages),
                "source_overlap_ns": max(0, overlap),
                "observed_parallel_execution": overlap > 0,
                "trust_scope": "LOCAL_CHAIN_AND_CAPTURED_SOURCE_LINK_CONSISTENCY_NOT_PROVIDER_ATTESTATION"}
    except (KeyError, TypeError, ValueError, IndexError, AttributeError):
        return _block("malformed retrospective evidence")
