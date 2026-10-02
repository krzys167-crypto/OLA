"""Standalone forensic evidence gate.

This module deliberately avoids importing OLA runtime/verifier code. It evaluates
an exported workstation evidence directory as an external artifact.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path


EXPECTED_AGENTS = [
    "codeact",
    "react",
    "agentic_rag",
    "mcp_tool_use",
    "self_reflection",
    "multi_agent",
]


def _gate(status: str, reason: str, **extra) -> dict:
    result = {"status": status, "reason": reason}
    result.update(extra)
    return result


def _load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain a JSON object")
    return value


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _verify_sha256_file(path: Path, expected_path: Path) -> tuple[bool, str]:
    text = expected_path.read_text(encoding="utf-8").strip()
    expected = text.split()[0] if text else ""
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    return actual == expected, f"expected={expected} actual={actual}"


def _verify_manifest_hashes(bundle: Path) -> dict:
    sums = bundle / "SHA256SUMS.txt"
    if not sums.exists():
        return _gate("UNKNOWN", "SHA256SUMS.txt missing")

    expected = {}
    for raw in sums.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            return _gate("BLOCKED", "malformed SHA256SUMS.txt entry", line=line)
        digest, name = parts
        name = name.strip()
        if len(digest) != 64:
            return _gate("BLOCKED", "invalid SHA256 digest in SHA256SUMS.txt", file=name)
        expected[name] = digest

    excluded = {"SHA256SUMS.txt", "freeze-anchor.json", "freeze-anchor.sha256"}
    actual_files = sorted(
        path.name for path in bundle.iterdir()
        if path.is_file() and path.name not in excluded
    )
    missing = sorted(set(actual_files) - set(expected))
    if missing:
        return _gate("BLOCKED", "artifact missing from SHA256SUMS.txt", missing=missing)

    mismatches = []
    for name in actual_files:
        actual = hashlib.sha256((bundle / name).read_bytes()).hexdigest()
        if actual != expected[name]:
            mismatches.append({
                "file": name,
                "expected": expected[name],
                "actual": actual,
            })
    if mismatches:
        return _gate("BLOCKED", "artifact hash mismatch", mismatches=mismatches)
    return _gate("VERIFIED", "all exported files match SHA256SUMS.txt", file_count=len(actual_files))


def _verify_source_binding(bundle: Path, expected_source_sha: str) -> dict:
    required = ["source.txt", "MANIFEST.json", "agent-run.json", "independent-verifier.json"]
    missing = [name for name in required if not (bundle / name).exists()]
    if missing:
        return _gate("UNKNOWN", "source-binding evidence missing", missing=missing)

    source_text = (bundle / "source.txt").read_text(encoding="utf-8")
    declared = None
    for line in source_text.splitlines():
        if line.startswith("commit="):
            declared = line.split("=", 1)[1].strip()
            break

    agent = _load_json(bundle / "agent-run.json")
    verifier = _load_json(bundle / "independent-verifier.json")
    manifest = _load_json(bundle / "MANIFEST.json")
    values = {
        "source.txt": declared,
        "agent-run.json": agent.get("source_commit"),
        "independent-verifier.json": verifier.get("source_commit"),
        "MANIFEST.json": manifest.get("source_commit"),
    }
    if any(value != expected_source_sha for value in values.values()):
        return _gate("BLOCKED", "SOURCE_SHA mismatch", values=values, expected=expected_source_sha)
    return _gate("VERIFIED", "all source identities equal expected SOURCE_SHA", source_sha=expected_source_sha)


def _verify_run_correlation(bundle: Path) -> dict:
    agent = _load_json(bundle / "agent-run.json")
    verifier = _load_json(bundle / "independent-verifier.json")
    manifest = _load_json(bundle / "MANIFEST.json")
    run_id = agent.get("run_id")
    values = {
        "agent-run.json": run_id,
        "independent-verifier.json": verifier.get("run_id"),
        "MANIFEST.json": manifest.get("run_id"),
    }
    trace_path = bundle / "provider-trace.json"
    if trace_path.exists():
        trace = _load_json(trace_path)
        values["provider-trace.json"] = {
            "calls": sorted({call.get("run_id") for call in trace.get("calls", [])}),
        }
        trace_runs = {call.get("run_id") for call in trace.get("calls", [])}
        if trace_runs != {run_id}:
            return _gate("BLOCKED", "provider trace run_id mismatch", values=values)
    if not run_id or any(value != run_id for key, value in values.items() if key != "provider-trace.json"):
        return _gate("BLOCKED", "run_id correlation mismatch", values=values)
    return _gate("VERIFIED", "runtime, verifier and manifest share one run_id", run_id=run_id)


def _verify_runtime_execution(bundle: Path, expected_source_sha: str) -> dict:
    data = _load_json(bundle / "agent-run.json")
    execution = data.get("execution")
    if data.get("evidence_count") != 6 or not isinstance(execution, list) or len(execution) != 6:
        return _gate("BLOCKED", "six-agent execution count mismatch", evidence_count=data.get("evidence_count"))

    names = [item.get("agent") for item in execution]
    if names != EXPECTED_AGENTS:
        return _gate("BLOCKED", "six-agent execution order mismatch", agents=names)

    for item in execution:
        if item.get("source_commit") != expected_source_sha:
            return _gate("BLOCKED", "agent execution source mismatch", agent=item.get("agent"))
        if item.get("provider") != "ollama":
            return _gate("BLOCKED", "unexpected provider", agent=item.get("agent"))
        if item.get("model") != "qwen2.5:0.5b-instruct":
            return _gate("BLOCKED", "unexpected model", agent=item.get("agent"))
        if item.get("invocation_type") != "real_llm":
            return _gate("BLOCKED", "non-real invocation", agent=item.get("agent"))
        if not item.get("response_id") and not item.get("response_digest"):
            return _gate("BLOCKED", "missing response identity", agent=item.get("agent"))
    return _gate("VERIFIED", "six real Ollama execution records are present", count=6)


def _verify_provider_trace(bundle: Path) -> dict:
    path = bundle / "provider-trace.json"
    if not path.exists():
        return _gate("UNKNOWN", "provider boundary trace missing")

    trace = _load_json(path)
    calls = trace.get("calls")
    if not isinstance(calls, list) or len(calls) != 6:
        return _gate("BLOCKED", "provider trace does not contain six calls")
    by_agent = {call.get("agent"): call for call in calls}
    if set(by_agent) != set(EXPECTED_AGENTS):
        return _gate("BLOCKED", "provider trace agent set mismatch")
    agent_run = _load_json(bundle / "agent-run.json")
    execution_by_agent = {item.get("agent"): item for item in agent_run.get("execution", [])}
    for call in calls:
        agent = call.get("agent")
        runtime = execution_by_agent.get(agent)
        if not call.get("run_id") or not call.get("response_digest") or not runtime:
            return _gate("BLOCKED", "provider trace lacks correlated runtime evidence", agent=agent)
        if call.get("run_id") != agent_run.get("run_id") or call.get("source_commit") != agent_run.get("source_commit"):
            return _gate("BLOCKED", "provider trace source/run correlation mismatch", agent=agent)
        if call.get("model") != "qwen2.5:0.5b-instruct" or runtime.get("model") != call.get("model"):
            return _gate("BLOCKED", "provider trace model mismatch", agent=agent)
        if call.get("response_digest") != runtime.get("response_digest"):
            return _gate("BLOCKED", "provider trace response digest mismatch", agent=agent)
    return _gate("VERIFIED", "provider boundary trace is internally consistent", count=6)


def _verify_provider_authenticity(bundle: Path) -> dict:
    # A local trace and local SHA-256 do not establish that the provider/server
    # was authentic rather than emulated. Keep this as an explicit intermediate
    # state until an external trust root is supplied.
    anchor = bundle / "provider-authenticity-external-anchor.json"
    if not anchor.exists():
        return _gate(
            "REVIEW_REQUIRED",
            "provider authenticity is not externally anchored",
            reason_code="LOCAL_TRACE_ONLY",
        )
    return _gate(
        "REVIEW_REQUIRED",
        "external provider anchor is present but requires a separately trusted verifier",
        reason_code="EXTERNAL_ANCHOR_NOT_INDEPENDENTLY_VERIFIED",
    )


OFFICIAL_QWEN25_05B_INSTRUCT_ID_PREFIX = "a8b0c5157701"

def _verify_source_signature(bundle: Path, expected_source_sha: str) -> dict:
    path = bundle / "github-source-verification.json"
    if not path.exists():
        return _gate("UNKNOWN", "GitHub source verification evidence missing")
    data = _load_json(path)
    verified = data.get("commit", {}).get("verification", {}).get("verified")
    sha = data.get("sha")
    if sha != expected_source_sha:
        return _gate("BLOCKED", "GitHub source verification SHA mismatch", observed_sha=sha, expected=expected_source_sha)
    if verified is not True:
        return _gate(
            "BLOCKED",
            "exact source commit is not cryptographically verified by GitHub",
            reason=data.get("commit", {}).get("verification", {}).get("reason"),
        )
    return _gate("VERIFIED", "GitHub independently reports cryptographically verified source commit", source_sha=expected_source_sha)


def _verify_physical_workstation(bundle: Path, expected_source_sha: str) -> dict:
    path = bundle / "workstation-registration.json"
    if not path.exists():
        return _gate("UNKNOWN", "physical workstation registration evidence missing")
    data = _load_json(path)
    if data.get("physical_execution") != "CAPTURED":
        return _gate("UNKNOWN", "physical execution has not been marked CAPTURED")
    if data.get("source_commit") != expected_source_sha:
        return _gate("BLOCKED", "physical workstation source SHA mismatch", observed_sha=data.get("source_commit"), expected=expected_source_sha)
    required = ["run_id", "agent_run_id", "hostname", "manufacturer", "model", "bios_serial_sha256"]
    missing = [key for key in required if not data.get(key)]
    if missing:
        return _gate("BLOCKED", "physical workstation registration incomplete", missing=missing)
    return _gate(
        "VERIFIED",
        "physical workstation registration is complete and source-bound",
        hostname=data.get("hostname"),
        model=data.get("model"),
        run_id=data.get("run_id"),
        agent_run_id=data.get("agent_run_id"),
    )


def _verify_image_and_model_digests(bundle: Path) -> dict:
    image = bundle / "docker-image.json"
    model = bundle / "ollama-model.json"
    if not image.exists() or not model.exists():
        return _gate("UNKNOWN", "container image/model digest evidence missing")
    image_data = _load_json(image)
    model_data = _load_json(model)
    image_id = image_data.get("image_id")
    model_digest = model_data.get("digest")
    if not isinstance(image_id, str) or not image_id.startswith("sha256:"):
        return _gate("BLOCKED", "Docker image content digest missing")
    if not isinstance(model_digest, str) or not model_digest.startswith("sha256:"):
        return _gate("BLOCKED", "Ollama model digest missing")
    digest_text = model_digest.split(":", 1)[1] if ":" in model_digest else model_digest
    registry_bound = digest_text.startswith(OFFICIAL_QWEN25_05B_INSTRUCT_ID_PREFIX)
    return _gate(
        "VERIFIED" if registry_bound else "REVIEW_REQUIRED",
        "Docker image and Ollama model content digests are captured",
        image_id=image_id,
        model_digest=model_digest,
        official_registry_id_prefix=OFFICIAL_QWEN25_05B_INSTRUCT_ID_PREFIX,
        model_registry_binding="VERIFIED" if registry_bound else "REVIEW_REQUIRED",
    )


def _verify_timing(bundle: Path) -> dict:
    window_path = bundle / "runtime-window.json"
    agent_path = bundle / "agent-run.json"
    if not window_path.exists() or not agent_path.exists():
        return _gate("UNKNOWN", "runtime timing evidence missing")
    window = _load_json(window_path)
    try:
        window_start = _parse_time(window["started_at"])
        window_end = _parse_time(window["ended_at"])
    except (KeyError, ValueError, TypeError):
        return _gate("BLOCKED", "runtime timing window is invalid")

    try:
        duration = float(window["duration_seconds"])
    except (KeyError, ValueError, TypeError):
        return _gate("BLOCKED", "runtime duration is invalid")
    if duration <= 0 or window_end <= window_start:
        return _gate("BLOCKED", "runtime timing window is non-positive")

    execution = _load_json(agent_path).get("execution", [])
    starts = []
    ends = []
    for item in execution:
        try:
            start = _parse_time(item["started_at"])
            end = _parse_time(item["ended_at"])
        except (KeyError, ValueError, TypeError):
            return _gate("BLOCKED", "agent timing evidence is incomplete", agent=item.get("agent"))
        if not start < end or start < window_start or end > window_end:
            return _gate("BLOCKED", "agent timing is outside runtime window", agent=item.get("agent"))
        starts.append(start)
        ends.append(end)

    if starts != sorted(starts) or ends != sorted(ends):
        return _gate("BLOCKED", "agent execution timestamps are not monotonic")
    return _gate("VERIFIED", "runtime and six-agent timing evidence is coherent", duration_seconds=duration)


def _verify_freeze_anchor(bundle: Path, expected_source_sha: str) -> dict:
    anchor = bundle / "freeze-anchor.json"
    anchor_hash = bundle / "freeze-anchor.sha256"
    if not anchor.exists() and not anchor_hash.exists():
        return _gate("REVIEW_REQUIRED", "freeze anchor is absent; external freeze remains open")
    if not anchor.exists() or not anchor_hash.exists():
        return _gate("BLOCKED", "freeze anchor is incomplete")

    data = _load_json(anchor)
    if data.get("source_sha") != expected_source_sha:
        return _gate("BLOCKED", "freeze anchor source SHA mismatch", source_sha=data.get("source_sha"))
    ok, detail = _verify_sha256_file(anchor, anchor_hash)
    if not ok:
        return _gate("BLOCKED", "freeze anchor hash mismatch", detail=detail)
    return _gate("VERIFIED", "freeze anchor content and hash are internally consistent")


def _verify_execution_integrity(bundle: Path) -> dict:
    path = bundle / "gate-results.json"
    if not path.exists():
        return _gate("UNKNOWN", "gate-results.json missing")
    data = _load_json(path)
    skipped = data.get("skipped", [])
    if skipped:
        return _gate("BLOCKED", "skipped gates are present", skipped=skipped)

    allowed_nonzero = {"tamper": 1}
    failures = []
    for name, gate in data.items():
        if name == "skipped" or not isinstance(gate, dict):
            continue
        if gate.get("status") != "VERIFIED":
            failures.append({"gate": name, "status": gate.get("status")})
            continue
        exit_code = gate.get("exit_code")
        if exit_code != 0 and not (name in allowed_nonzero and exit_code == 1):
            failures.append({"gate": name, "exit_code": exit_code})
    if failures:
        return _gate("BLOCKED", "gate execution integrity failed", failures=failures)
    return _gate("VERIFIED", "no skipped gates and required exit codes are valid")


def evaluate_forensic_bundle(
    bundle_dir: str | Path,
    expected_source_sha: str,
    *,
    zip_path: str | Path | None = None,
    zip_sha_path: str | Path | None = None,
) -> dict:
    bundle = Path(bundle_dir)
    gates = {}

    if zip_path is None or zip_sha_path is None:
        gates["archive_integrity"] = _gate(
            "REVIEW_REQUIRED",
            "ZIP hash was not supplied; external archive anchoring remains open",
        )
    else:
        ok, detail = _verify_sha256_file(Path(zip_path), Path(zip_sha_path))
        gates["archive_integrity"] = _gate("VERIFIED" if ok else "BLOCKED", detail)

    gates["artifact_hashes"] = _verify_manifest_hashes(bundle)

    for filename in ["MANIFEST.json", "agent-run.json", "independent-verifier.json", "provider-trace.json", "docker-image.json", "ollama-model.json", "runtime-window.json", "gate-results.json"]:
        if not (bundle / filename).exists():
            # Later gates carry their own precise UNKNOWN state.
            continue

    gates["source_binding"] = _verify_source_binding(bundle, expected_source_sha)
    gates["source_signature"] = _verify_source_signature(bundle, expected_source_sha)
    gates["run_correlation"] = _verify_run_correlation(bundle)
    gates["runtime_execution"] = _verify_runtime_execution(bundle, expected_source_sha)
    gates["provider_trace_integrity"] = _verify_provider_trace(bundle)
    gates["provider_authenticity"] = _verify_provider_authenticity(bundle)
    gates["image_model_digests"] = _verify_image_and_model_digests(bundle)
    gates["timing"] = _verify_timing(bundle)
    gates["execution_integrity"] = _verify_execution_integrity(bundle)
    gates["physical_workstation"] = _verify_physical_workstation(bundle, expected_source_sha)
    gates["freeze_anchor"] = _verify_freeze_anchor(bundle, expected_source_sha)

    verifier_path = bundle / "independent-verifier.json"
    runtime_component = None
    verifier_component = None
    if verifier_path.exists():
        verifier = _load_json(verifier_path)
        runtime_component = verifier.get("runtime_component")
        verifier_component = verifier.get("verifier_component")
        gates["independence_boundary"] = _gate(
            "VERIFIED"
            if verifier.get("status") == "VERIFIED"
            and runtime_component
            and verifier_component
            and runtime_component != verifier_component
            else "BLOCKED",
            "runtime and forensic verifier are separate declared components",
            runtime_component=runtime_component,
            verifier_component=verifier_component,
        )
    else:
        gates["independence_boundary"] = _gate("UNKNOWN", "independent verifier evidence missing")

    statuses = [gate["status"] for gate in gates.values()]
    if "BLOCKED" in statuses:
        overall = "BLOCKED"
    elif "UNKNOWN" in statuses:
        overall = "UNKNOWN"
    elif "REVIEW_REQUIRED" in statuses:
        overall = "REVIEW_REQUIRED"
    else:
        overall = "VERIFIED"

    return {
        "schema": "ola-forensic-gate/v1",
        "source_sha": expected_source_sha,
        "status": overall,
        "gates": gates,
    }


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Verify an exported OLA workstation evidence bundle.")
    parser.add_argument("--bundle-dir", required=True)
    parser.add_argument("--expected-source-sha", required=True)
    parser.add_argument("--zip")
    parser.add_argument("--zip-sha256")
    parser.add_argument("--output")
    args = parser.parse_args()

    report = evaluate_forensic_bundle(
        args.bundle_dir,
        args.expected_source_sha,
        zip_path=args.zip,
        zip_sha_path=args.zip_sha256,
    )
    rendered = json.dumps(report, sort_keys=True, indent=2)
    print(rendered)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    return {"VERIFIED": 0, "REVIEW_REQUIRED": 2, "UNKNOWN": 3, "BLOCKED": 1}[report["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
