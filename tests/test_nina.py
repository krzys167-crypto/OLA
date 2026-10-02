import json
import uuid

import pytest

from app.nina import NinaOrchestrator, NinaTask


def test_nina_creates_deterministic_task_contract():
    task = NinaTask.create("tenant-1", "Calculate 17 * 23", ["safe_expression"])
    assert task.tenant_id == "tenant-1"
    assert task.task == "Calculate 17 * 23"
    assert task.requested_tools == ("safe_expression",)
    assert task.task_id


def test_nina_rejects_empty_task():
    with pytest.raises(ValueError, match="task is required"):
        NinaTask.create("tenant-1", "", [])


def test_nina_denies_unknown_tool():
    orchestrator = NinaOrchestrator()
    task = NinaTask.create("tenant-1", "Calculate 17 * 23", ["shell"])
    decision = orchestrator.plan(task)
    assert decision.status == "BLOCK"
    assert decision.allowed_tools == ()
    assert "unknown tool" in decision.reason


def test_nina_allows_registered_tool():
    orchestrator = NinaOrchestrator()
    task = NinaTask.create("tenant-1", "Calculate 17 * 23", ["safe_expression"])
    decision = orchestrator.plan(task)
    assert decision.status == "ALLOW"
    assert decision.allowed_tools == ("safe_expression",)

from app.agent_runtime import AGENT_ROLES, _invoke_llm, run_agent_task
from app.database import SessionLocal
from app.models import EvidenceRecord, Tenant
from app.igor import IgorVerifier
from app.hashchain import GENESIS_HASH, canonical_json, compute_record_hash
from scripts.verify_agent_runtime import verify


def _seed_runtime_tenant():
    tenant_id = f"semantic-{uuid.uuid4()}"
    db = SessionLocal()
    db.add(Tenant(id=tenant_id, name="semantic-closure-test"))
    db.commit()
    db.close()
    return tenant_id


def test_real_llm_output_is_causal(monkeypatch):
    tenant_id = _seed_runtime_tenant()
    monkeypatch.setenv("OLA_LLM_MODE", "required")
    monkeypatch.setenv("OLA_LLM_PROVIDER", "openai")

    def fake_llm(*args, **kwargs):
        return {
            "provider": "openai",
            "model": "test-model",
            "invocation_type": "real_llm",
            "prompt_digest": "p",
            "output": '{"action":"safe_expression","result":"392"}',
            "response_id": "resp-test",
        }

    monkeypatch.setattr("app.agent_runtime._invoke_llm", fake_llm)

    with pytest.raises(RuntimeError, match="LLM proposed result"):
        run_agent_task(tenant_id, "Calculate 17 * 23 and return the verified result.")


def test_runtime_evidence_contains_canonical_source_sha(monkeypatch):
    tenant_id = _seed_runtime_tenant()
    source_sha = "source-sha-test"
    monkeypatch.setenv("OLA_SOURCE_COMMIT", source_sha)

    result = run_agent_task(tenant_id, "verify source binding")

    db = SessionLocal()
    rows = db.query(EvidenceRecord).filter(EvidenceRecord.tenant_id == tenant_id).order_by(EvidenceRecord.seq.asc()).all()
    db.close()
    assert result["source_commit"] == source_sha
    assert len(rows) == 6
    assert all(json.loads(row.payload_json)["source_commit"] == source_sha for row in rows)


def test_independent_verifier_rejects_source_commit_mismatch(monkeypatch):
    tenant_id = _seed_runtime_tenant()
    monkeypatch.setenv("OLA_SOURCE_COMMIT", "source-sha-canonical")

    result = run_agent_task(tenant_id, "verify source binding")

    verified = verify(
        tenant_id,
        result["run_id"],
        expected_commit="source-sha-other",
        expected_task="verify source binding",
        expected_result=result["final_result"],
    )
    assert verified["status"] == "BLOCK"


def test_ollama_without_provider_id_keeps_response_digest(monkeypatch):
    monkeypatch.setenv("OLA_LLM_PROVIDER", "ollama")
    monkeypatch.setenv("OLA_LLM_MODE", "required")
    monkeypatch.setenv("OLA_LLM_MODEL", "qwen2.5:0.5b-instruct")

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "model": "qwen2.5:0.5b-instruct",
                "message": {"content": '{"action":"safe_expression","result":"391"}'},
            }

    import httpx
    monkeypatch.setattr(httpx, "post", lambda *args, **kwargs: FakeResponse())

    evidence = _invoke_llm("codeact", "Calculate 17 * 23", {})
    assert evidence["response_id"] is None
    assert evidence["response_digest"]


from scripts.forensic_gate import evaluate_forensic_bundle


def _write_complete_forensic_bundle(tmp_path, *, source="df9f8783248812c2c887cc9805524602f4dc3ef2"):
    import hashlib

    (tmp_path / "source.txt").write_text(f"commit={source}\n")
    (tmp_path / "agent-run.json").write_text(
        json.dumps({
            "run_id": "run-1",
            "source_commit": source,
            "execution": [
                {
                    "agent": name,
                    "started_at": f"2026-10-02T20:{10+i:02d}:00+00:00",
                    "ended_at": f"2026-10-02T20:{10+i:02d}:01+00:00",
                    "provider": "ollama",
                    "model": "qwen2.5:0.5b-instruct",
                    "invocation_type": "real_llm",
                    "response_digest": f"digest-{i}",
                }
                for i, name in enumerate(
                    ["codeact", "react", "agentic_rag", "mcp_tool_use", "self_reflection", "multi_agent"]
                )
            ],
            "evidence_count": 6,
        }, sort_keys=True)
    )
    docker_archive = tmp_path / "docker-image.tar"
    docker_archive.write_bytes(b"synthetic-docker-image")
    docker_archive_hash = hashlib.sha256(docker_archive.read_bytes()).hexdigest()
    (tmp_path / "docker-image.json").write_text(json.dumps({
        "image_id": "sha256:" + "a" * 64,
        "archive": "docker-image.tar",
        "archive_sha256": docker_archive_hash,
    }))
    (tmp_path / "ollama-model.json").write_text(
        json.dumps({"model": "qwen2.5:0.5b-instruct", "digest": "sha256:" + "b" * 64})
    )
    (tmp_path / "runtime-window.json").write_text(json.dumps({
        "started_at": "2026-10-02T20:10:00+00:00",
        "ended_at": "2026-10-02T20:17:00+00:00",
        "duration_seconds": 420,
    }))
    (tmp_path / "gate-results.json").write_text(json.dumps({
        "source_pin": {"status": "VERIFIED", "exit_code": 0},
        "image_build": {"status": "VERIFIED", "exit_code": 0},
        "pytest": {"status": "VERIFIED", "exit_code": 0},
        "runtime": {"status": "VERIFIED", "exit_code": 0},
        "independent_verify": {"status": "VERIFIED", "exit_code": 0},
        "tamper": {"status": "VERIFIED", "exit_code": 1},
        "stability": {"status": "VERIFIED", "exit_code": 0},
        "skipped": [],
    }, sort_keys=True))
    (tmp_path / "provider-trace.json").write_text(json.dumps({
        "runtime_component": "ola-runtime-v2",
        "verifier_component": "ola-forensic-gate-v1",
        "calls": [
            {
                "agent": name,
                "run_id": "run-1",
                "source_commit": source,
                "response_digest": f"digest-{i}",
                "model": "qwen2.5:0.5b-instruct",
                "started_at": f"2026-10-02T20:{10+i:02d}:00+00:00",
                "ended_at": f"2026-10-02T20:{10+i:02d}:01+00:00",
            }
            for i, name in enumerate(
                ["codeact", "react", "agentic_rag", "mcp_tool_use", "self_reflection", "multi_agent"]
            )
        ],
    }, sort_keys=True))
    (tmp_path / "independent-verifier.json").write_text(json.dumps({
        "status": "VERIFIED",
        "verifier_component": "ola-forensic-gate-v1",
        "runtime_component": "ola-runtime-v2",
        "run_id": "run-1",
        "source_commit": source,
    }, sort_keys=True))
    (tmp_path / "github-source-verification.json").write_text(json.dumps({
        "sha": source,
        "commit": {"verification": {"verified": True, "reason": "valid"}},
    }, sort_keys=True))
    (tmp_path / "workstation-registration.json").write_text(json.dumps({
        "physical_execution": "CAPTURED",
        "source_commit": source,
        "run_id": "registration-1",
        "agent_run_id": "run-1",
        "hostname": "TEST-ZBOOK",
        "manufacturer": "HP",
        "model": "ZBook",
        "bios_serial_sha256": "c" * 64,
    }, sort_keys=True))
    manifest = {
        "run_id": "run-1",
        "source_commit": source,
        "physical_execution": "CAPTURED",
    }
    (tmp_path / "MANIFEST.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")

    (tmp_path / "SHA256SUMS.txt").write_text("")
    sums = []
    for file in sorted(tmp_path.iterdir()):
        if file.name == "SHA256SUMS.txt":
            continue
        digest = hashlib.sha256(file.read_bytes()).hexdigest()
        sums.append(f"{digest}  {file.name}")
    (tmp_path / "SHA256SUMS.txt").write_text("\n".join(sums) + "\n")
    return tmp_path


def test_forensic_gate_complete_bundle_requires_external_authenticity_review(tmp_path):
    bundle = _write_complete_forensic_bundle(tmp_path)
    report = evaluate_forensic_bundle(bundle, "df9f8783248812c2c887cc9805524602f4dc3ef2")
    assert report["status"] == "REVIEW_REQUIRED"
    assert all(
        item["status"] == "VERIFIED"
        for name, item in report["gates"].items()
        if name not in {"provider_authenticity", "archive_integrity", "freeze_anchor"}
    )
    assert report["gates"]["provider_authenticity"]["status"] == "REVIEW_REQUIRED"


def test_forensic_gate_blocks_source_mismatch(tmp_path):
    bundle = _write_complete_forensic_bundle(
        tmp_path,
        source="0000000000000000000000000000000000000000",
    )
    report = evaluate_forensic_bundle(bundle, "df9f8783248812c2c887cc9805524602f4dc3ef2")
    assert report["status"] == "BLOCKED"
    assert report["gates"]["source_binding"]["status"] == "BLOCKED"


def test_forensic_gate_requires_review_when_provider_authenticity_is_not_external(tmp_path):
    bundle = _write_complete_forensic_bundle(tmp_path)
    (tmp_path / "provider-trace.json").write_text(json.dumps({
        "runtime_component": "ola-runtime-v2",
        "verifier_component": "ola-forensic-gate-v1",
        "calls": json.loads((tmp_path / "provider-trace.json").read_text())["calls"],
        "external_anchor": False,
    }, sort_keys=True))
    (tmp_path / "SHA256SUMS.txt").write_text("")
    import hashlib
    sums = []
    for file in sorted(tmp_path.iterdir()):
        if file.name == "SHA256SUMS.txt":
            continue
        sums.append(f"{hashlib.sha256(file.read_bytes()).hexdigest()}  {file.name}")
    (tmp_path / "SHA256SUMS.txt").write_text("\n".join(sums) + "\n")
    report = evaluate_forensic_bundle(bundle, "df9f8783248812c2c887cc9805524602f4dc3ef2")
    assert report["gates"]["provider_authenticity"]["status"] == "REVIEW_REQUIRED"
    assert report["status"] == "REVIEW_REQUIRED"


def test_forensic_gate_blocks_missing_skip_and_nonzero_exit_evidence(tmp_path):
    bundle = _write_complete_forensic_bundle(tmp_path)
    (tmp_path / "gate-results.json").write_text(json.dumps({
        "source_pin": {"status": "VERIFIED", "exit_code": 0},
        "image_build": {"status": "VERIFIED", "exit_code": 0},
        "pytest": {"status": "VERIFIED", "exit_code": 0},
        "runtime": {"status": "VERIFIED", "exit_code": 0},
        "independent_verify": {"status": "VERIFIED", "exit_code": 0},
        "tamper": {"status": "VERIFIED", "exit_code": 1},
        "stability": {"status": "VERIFIED", "exit_code": 0},
        "skipped": ["stability"],
    }, sort_keys=True))
    report = evaluate_forensic_bundle(bundle, "df9f8783248812c2c887cc9805524602f4dc3ef2")
    assert report["gates"]["execution_integrity"]["status"] == "BLOCKED"
    assert report["status"] == "BLOCKED"


def test_agent_runtime_records_real_execution_timestamps(monkeypatch):
    tenant_id = _seed_runtime_tenant()
    monkeypatch.setenv("OLA_SOURCE_COMMIT", "source-sha-timing")
    result = run_agent_task(tenant_id, "timing proof")
    execution = result["execution"]
    assert len(execution) == 6
    starts = [item["started_at"] for item in execution]
    ends = [item["ended_at"] for item in execution]
    assert all(starts[i] < ends[i] for i in range(6))
    assert starts == sorted(starts)
    assert ends == sorted(ends)


def test_igor_rejects_mixed_source_commits():
    tenant_id = "igor-source-test"
    records = []
    previous = GENESIS_HASH
    for seq, agent in enumerate(AGENT_ROLES):
        source = "canonical-source" if seq < 5 else "other-source"
        payload = {
            "run_id": "run-1",
            "agent": agent,
            "task": "task",
            "tool_output": "391",
            "result": "391",
            "commit": "canonical-source",
            "source_commit": source,
            "capability": agent,
            "provider": "ollama",
            "model": "qwen2.5:0.5b-instruct",
            "invocation_type": "real_llm",
            "response_ids": [f"resp-{seq}"],
        }
        payload_json = canonical_json(payload)
        record_hash = compute_record_hash(tenant_id, seq, previous, payload_json)
        records.append({
            "id": f"e-{seq}",
            "tenant_id": tenant_id,
            "seq": seq,
            "record_type": f"agent.{agent}",
            "payload_json": payload_json,
            "prev_hash": previous,
            "record_hash": record_hash,
        })
        previous = record_hash

    result = IgorVerifier().verify_records(
        records,
        expected_commit="canonical-source",
        expected_task="task",
        expected_result="391",
        expected_provider="ollama",
        expected_model="qwen2.5:0.5b-instruct",
        expected_run_id="run-1",
    )
    assert result.status == "BLOCK"
    assert result.reason == "commit/source_commit provenance mismatch"


def test_real_llm_requires_fresh_replay_nonce(monkeypatch):
    tenant_id = _seed_runtime_tenant()
    monkeypatch.setenv("OLA_LLM_MODE", "required")
    monkeypatch.setenv("OLA_LLM_PROVIDER", "ollama")
    monkeypatch.delenv("OLA_REPLAY_NONCE", raising=False)
    with pytest.raises(RuntimeError, match="OLA_REPLAY_NONCE"):
        run_agent_task(tenant_id, "Calculate 17 * 23 and return the verified result.")


def test_independent_verifier_rejects_missing_or_mismatched_replay_nonce(monkeypatch):
    tenant_id = _seed_runtime_tenant()
    source_sha = "source-sha-nonce"
    nonce = "ab" * 32
    monkeypatch.setenv("OLA_SOURCE_COMMIT", source_sha)
    monkeypatch.setenv("OLA_REPLAY_NONCE", nonce)
    result = run_agent_task(tenant_id, "verify nonce binding")

    assert result["replay_nonce"] == nonce
    assert verify(
        tenant_id,
        result["run_id"],
        expected_commit=source_sha,
        expected_task="verify nonce binding",
        expected_result=result["final_result"],
        expected_nonce=nonce + "00",
    )["status"] == "BLOCK"


def test_forensic_gate_blocks_replay_nonce_mismatch(tmp_path):
    bundle = _write_complete_forensic_bundle(tmp_path)
    source = "df9f8783248812c2c887cc9805524602f4dc3ef2"
    (tmp_path / "run-challenge.json").write_text(json.dumps({
        "schema": "ola-run-challenge/v1",
        "run_id": "run-1",
        "source_commit": source,
        "replay_nonce": "ab" * 32,
    }, sort_keys=True))
    data = json.loads((tmp_path / "agent-run.json").read_text())
    data["replay_nonce"] = "cd" * 32
    (tmp_path / "agent-run.json").write_text(json.dumps(data, sort_keys=True))
    for file in sorted(tmp_path.iterdir()):
        if file.name == "SHA256SUMS.txt":
            continue
    sums=[]
    import hashlib
    for file in sorted(tmp_path.iterdir()):
        if file.name != "SHA256SUMS.txt":
            sums.append(f"{hashlib.sha256(file.read_bytes()).hexdigest()}  {file.name}")
    (tmp_path / "SHA256SUMS.txt").write_text("\n".join(sums) + "\n")
    report = evaluate_forensic_bundle(tmp_path, source)
    assert report["gates"]["anti_replay"]["status"] == "BLOCKED"
    assert report["status"] == "BLOCKED"
