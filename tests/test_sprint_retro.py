"""Sprint retro integration contract: same DAG runtime and independent IGOR."""
import threading
import uuid

import pytest

from app.main import append_record, read_tenant_evidence
from app.sprint_retro import run_sprint_retro, RetroBlocked


CYCLE = "cycle-test-2026w42"
START = "2026-10-05T00:00:00Z"
END = "2026-10-12T00:00:00Z"


def source_items():
    tickets = [
        {"id": f"LIN-{i}", "title": f"Task {i}", "url": f"https://linear.app/demo/issue/LIN-{i}",
         "outcome": "shipped" if i % 2 else "slipped",
         "cycle_time_hours": 12 * i, "rescoped": i == 3}
        for i in range(1, 5)
    ]
    messages = [
        {"url": f"https://app.slack.com/archives/C123/p172000000000000{i}",
         "text": ("blocked by API" if i == 1 else "nice shipped 🎉"),
         "sent_at": "2026-10-07T12:00:00Z",
         "reactions": ["tada"] if i > 1 else []}
        for i in range(1, 5)
    ]
    return tickets, messages


def compose(tickets, messages):
    linear = [t["url"] for t in tickets]
    slack = [m["url"] for m in messages]
    return {
        "went_well": [{"text": f"Shipped work referenced by {i}",
                        "refs": [linear[i % 4], slack[1]]} for i in range(3)],
        "dragged": [{"text": f"Investigate delay {i}",
                      "refs": [linear[(i + 1) % 4], slack[0]]} for i in range(3)],
        "try_next_sprint": [{"text": f"Try earlier escalation {i}",
                             "refs": [linear[i % 4], slack[0]]} for i in range(3)],
        "process_change": "Escalate blockers in the team channel within one working day",
        "confidence": 0.65,
    }


def test_one_markdown_document_parallel_sources_and_igor(monkeypatch):
    monkeypatch.setenv("OLA_RUNTIME_COMMIT", "retro-ci-head")
    tickets, messages = source_items()
    barrier = threading.Barrier(2, timeout=4)

    def linear(cycle_id):
        assert cycle_id == CYCLE
        barrier.wait()
        return {"cycle_id": CYCLE, "closed": True, "tickets": tickets}

    def slack(channel, start, end):
        assert (channel, start, end) == ("C123", START, END)
        barrier.wait()
        return {"channel_id": "C123", "messages": messages}

    tenant = "retro-" + str(uuid.uuid4())
    out = run_sprint_retro(tenant_id=tenant, requester_id="requester",
        cycle_id=CYCLE, channel_id="C123", start=START, end=END,
        linear_reader=linear, slack_reader=slack, synthesizer=compose,
        append=append_record, fetch_records=read_tenant_evidence)
    assert out["status"] == "COMPLETED_UNVERIFIED"
    assert out["igor"]["status"] == "VERIFIED", out
    assert out["human_gate"] == "NOT_APPROVED"
    assert out["verified"] is False
    assert out["document"].count("## Went well") == 1
    assert out["document"].count("## Dragged") == 1
    assert out["document"].count("## Try next sprint") == 1
    assert out["document"].count("](https://") >= 9
    assert out["document_sha256"]
    assert out["igor"]["verified_nodes"] == 4


def test_missing_connectors_fail_closed_before_writes():
    writes = []
    with pytest.raises(RetroBlocked, match="connectors"):
        run_sprint_retro(tenant_id="test", requester_id="x", cycle_id=CYCLE,
            channel_id="C123", start=START, end=END,
            append=lambda *args: writes.append(args), fetch_records=lambda _: [])
    assert writes == []


@pytest.mark.parametrize("modify", ["not_closed", "fake_link", "missing_cycle", "outside_window", "wrong_channel_link"])
def test_bad_sources_or_uncited_claim_never_returns_document(monkeypatch, modify):
    monkeypatch.setenv("OLA_RUNTIME_COMMIT", "retro-ci-head")
    tickets, messages = source_items()

    if modify == "outside_window":
        messages[0]["sent_at"] = "2026-12-20T00:00:00Z"
    if modify == "wrong_channel_link":
        messages[0]["url"] = messages[0]["url"].replace("/archives/C123/", "/archives/C999/")

    def linear(cycle_id):
        return {"cycle_id": "wrong" if modify == "missing_cycle" else CYCLE,
                "closed": modify != "not_closed", "tickets": tickets}

    def synth(t, m):
        output = compose(t, m)
        if modify == "fake_link":
            output["went_well"][0]["refs"] = ["https://linear.app/demo/issue/LIN-FAKE"]
        return output

    with pytest.raises(RetroBlocked):
        run_sprint_retro(tenant_id="retro-" + str(uuid.uuid4()),
            requester_id="requester", cycle_id=CYCLE, channel_id="C123",
            start=START, end=END, linear_reader=linear,
            slack_reader=lambda channel, start, end: {"channel_id": channel, "messages": messages},
            synthesizer=synth, append=append_record, fetch_records=read_tenant_evidence)


def test_document_never_promoted_when_igor_rejects_trace(monkeypatch):
    monkeypatch.setenv("OLA_RUNTIME_COMMIT", "retro-ci-head")
    tickets, messages = source_items()
    with pytest.raises(RetroBlocked, match="IGOR"):
        run_sprint_retro(tenant_id="retro-" + str(uuid.uuid4()),
            requester_id="requester", cycle_id=CYCLE, channel_id="C123",
            start=START, end=END,
            linear_reader=lambda _: {"cycle_id": CYCLE, "closed": True, "tickets": tickets},
            slack_reader=lambda *_: {"channel_id": "C123", "messages": messages},
            synthesizer=compose, append=append_record,
            fetch_records=lambda _: [])



def test_igor_rejects_rehashed_evidence_with_invented_citation(monkeypatch):
    """A recomputed local chain alone cannot authorize a fabricated link."""
    import json
    from app.hashchain import canonical_json, compute_record_hash_v2, EVIDENCE_META_KEY
    from app.workflow_engine import _digest
    from app.igor_sprint_retro import verify_sprint_retro_records
    monkeypatch.setenv("OLA_RUNTIME_COMMIT", "retro-ci-head")
    tickets, messages = source_items()
    barrier = threading.Barrier(2, timeout=4)

    def linear(_):
        barrier.wait()
        return {"cycle_id": CYCLE, "closed": True, "tickets": tickets}

    def slack(channel, start, end):
        barrier.wait()
        return {"channel_id": channel, "messages": messages}

    tenant = "retro-" + str(uuid.uuid4())
    result = run_sprint_retro(tenant_id=tenant, requester_id="requester",
        cycle_id=CYCLE, channel_id="C123", start=START, end=END,
        linear_reader=linear, slack_reader=slack, synthesizer=compose,
        append=append_record, fetch_records=read_tenant_evidence)
    events = [json.loads(row["payload_json"]) for row in read_tenant_evidence(tenant)]
    invented = "https://linear.app/demo/issue/LIN-FAKE"
    synthesis = next(event for event in events
                     if event.get("event") == "task.completed"
                     and event.get("node_id") == "synthesis")
    synthesis["output"]["went_well"][0]["refs"] = [invented]
    synthesis["output_digest"] = _digest(synthesis["output"])
    document_start = next(event for event in events
                          if event.get("event") == "task.started"
                          and event.get("node_id") == "document")
    document_start["input_digest"] = _digest({
        "task": "Produce one Markdown draft",
        "deps": {"synthesis": synthesis["output"]},
    })
    previous = "0" * 64
    forged = []
    for seq, event in enumerate(events):
        raw = canonical_json(event)
        meta = event[EVIDENCE_META_KEY]
        digest = compute_record_hash_v2(tenant, seq, previous, meta["record_type"], meta["producer"], raw)
        forged.append({"tenant_id": tenant, "seq": seq, "prev_hash": previous,
                       "record_hash": digest, "payload_json": raw,
                       "record_type": event["event"]})
        previous = digest
    verdict = verify_sprint_retro_records(forged, tenant_id=tenant,
         run_id=result["run_id"], cycle_id=CYCLE, expected_commit="retro-ci-head")
    assert verdict["status"] == "BLOCK", verdict
    assert "invented" in verdict["reason"], verdict


def test_retro_markdown_escapes_untrusted_links():
    from app.sprint_retro import _safe_markdown
    literal = "[action](https://attacker.example) ![img](https://attacker.example/i)"
    escaped = _safe_markdown(literal)
    assert "[action](" not in escaped
    assert "![img](" not in escaped
    assert "\\[action\\]" in escaped
    assert "\\!\\[img\\]" in escaped


def test_igor_accepts_fast_nonoverlapping_parallel_reads(monkeypatch):
    # Deliberately non-overlapping test source callbacks: the valid DAG
    # topology is parallel, but instant reads do not guarantee clock overlap.
    from app.igor_sprint_retro import verify_sprint_retro_records
    import json
    from app.hashchain import canonical_json, compute_record_hash_v2, EVIDENCE_META_KEY
    import app.sprint_retro as retro
    monkeypatch.setenv("OLA_RUNTIME_COMMIT", "retro-ci-head")
    tickets, messages = source_items()
    tenant = "retro-" + str(uuid.uuid4())
    out = run_sprint_retro(tenant_id=tenant, requester_id="reviewer",
        cycle_id=CYCLE, channel_id="C123", start=START, end=END,
        linear_reader=lambda _: {"cycle_id": CYCLE, "closed": True, "tickets": tickets},
        slack_reader=lambda *_: {"channel_id": "C123", "messages": messages},
        synthesizer=compose, append=append_record, fetch_records=read_tenant_evidence)
    rows = read_tenant_evidence(tenant)
    events = [json.loads(row["payload_json"]) for row in rows]
    completed = {e["node_id"]: e for e in events if e["event"] == "task.completed"}
    # Force disjoint valid client intervals, preserving each started < finished.
    completed["linear"]["worker_started_ns"] = 100
    completed["linear"]["worker_finished_ns"] = 200
    completed["slack"]["worker_started_ns"] = 300
    completed["slack"]["worker_finished_ns"] = 400
    forged, prev = [], "0" * 64
    for seq, event in enumerate(events):
        raw = canonical_json(event)
        meta = event[EVIDENCE_META_KEY]
        digest = compute_record_hash_v2(tenant, seq, prev, meta["record_type"], meta["producer"], raw)
        forged.append({"tenant_id": tenant, "seq": seq, "prev_hash": prev,
                       "record_hash": digest, "record_type": event["event"],
                       "payload_json": raw})
        prev = digest
    verdict = verify_sprint_retro_records(forged, tenant_id=tenant,
        run_id=out["run_id"], cycle_id=CYCLE, expected_commit="retro-ci-head")
    assert verdict["status"] == "VERIFIED", verdict
    assert verdict["source_overlap_ns"] == 0
    assert verdict["observed_parallel_execution"] is False



def test_rehashed_retrospective_document_must_match_recorded_synthesis(monkeypatch):
    from app.igor_sprint_retro import verify_sprint_retro_records
    from app.workflow_engine import _digest
    from app.hashchain import canonical_json, compute_record_hash_v2, EVIDENCE_META_KEY
    import hashlib
    import json
    monkeypatch.setenv("OLA_RUNTIME_COMMIT", "retro-ci-head")
    tickets, messages = source_items()
    tenant = "retro-" + str(uuid.uuid4())
    out = run_sprint_retro(tenant_id=tenant, requester_id="reviewer",
        cycle_id=CYCLE, channel_id="C123", start=START, end=END,
        linear_reader=lambda _: {"cycle_id": CYCLE, "closed": True, "tickets": tickets},
        slack_reader=lambda *_: {"channel_id": "C123", "messages": messages},
        synthesizer=compose, append=append_record, fetch_records=read_tenant_evidence)
    events = [json.loads(row["payload_json"]) for row in read_tenant_evidence(tenant)]
    document = next(event for event in events if event.get("event") == "task.completed"
                    and event.get("node_id") == "document")
    content = document["output"]["markdown"]
    assert "Shipped work referenced by 0" in content
    document["output"]["markdown"] = content.replace(
        "Shipped work referenced by 0", "Falsified business outcome", 1)
    document["output"]["sha256"] = hashlib.sha256(
        document["output"]["markdown"].encode()).hexdigest()
    document["output_digest"] = _digest(document["output"])
    records, prev = [], "0" * 64
    for seq, event in enumerate(events):
        raw = canonical_json(event)
        meta = event[EVIDENCE_META_KEY]
        digest = compute_record_hash_v2(tenant, seq, prev, meta["record_type"], meta["producer"], raw)
        records.append({"tenant_id": tenant, "seq": seq, "prev_hash": prev,
                        "record_hash": digest, "record_type": event["event"],
                        "payload_json": raw})
        prev = digest
    verdict = verify_sprint_retro_records(records, tenant_id=tenant,
        run_id=out["run_id"], cycle_id=CYCLE, expected_commit="retro-ci-head")
    assert verdict["status"] == "BLOCK", verdict
    assert "differs" in verdict["reason"]
