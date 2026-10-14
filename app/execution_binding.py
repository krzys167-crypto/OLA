"""Local source/policy binding. No remote attestation or trusted clock claim."""
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "policies/nina-review-v1.json"


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def capture_manifest_source(root):
    """Check build inventory locally; manifest is NOT a signed source attestation."""
    root = Path(root)
    try:
        manifest_path = root / "source-manifest.json"
        if manifest_path.is_symlink():
            raise ValueError("symlinked manifest")
        def unique(pairs):
            obj = {}
            for key, value in pairs:
                if key in obj:
                    raise ValueError("duplicate manifest key")
                obj[key] = value
            return obj
        manifest = json.loads(manifest_path.read_bytes(), object_pairs_hook=unique)
        if set(manifest) != {"schema", "source_sha", "files"} or manifest["schema"] != "ola-local-build-v1":
            raise ValueError("unsupported source manifest")
        sha, expected = manifest["source_sha"], manifest["files"]
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise ValueError("invalid manifest source SHA")
        if os.getenv("OLA_RUNTIME_COMMIT") not in (None, "", sha):
            raise ValueError("runtime SHA differs from build manifest")
        if not isinstance(expected, dict):
            raise ValueError("invalid manifest inventory")
        actual = {}
        for directory in (root / "app", root / "policies"):
            if directory.is_symlink() or not directory.is_dir():
                raise ValueError("missing or symlinked source directory")
            for path in directory.rglob("*"):
                if path.is_symlink():
                    raise ValueError("symlink in source boundary")
                if "__pycache__" in path.relative_to(root).parts:
                    continue
                if path.is_file():
                    actual[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        if "app/main.py" not in actual or "policies/nina-review-v1.json" not in actual or actual != expected:
            raise ValueError("source bytes differ from build inventory")
        return {"status": "LOCAL", "sha": sha, "files_digest": digest(actual),
                "boundary": "unsigned-build-inventory-on-disk-v1"}
    except (OSError, ValueError, TypeError, KeyError) as exc:
        return {"status": "UNKNOWN", "reason": str(exc)}


def capture_source(root=ROOT):
    """Compare on-disk application and policy bytes to a concrete Git tree.

    This does not prove loaded process memory, dependency provenance or host trust.
    Refuse symlinks, dirty bytes and untracked Python/policy files in this boundary.
    """
    root = Path(root).resolve()
    # Explicit mode only; a failed Git check must never fall back to a manifest.
    mode = os.getenv("OLA_SOURCE_MODE", "git")
    if mode == "build-inventory":
        return capture_manifest_source(root)
    if mode != "git":
        return {"status": "UNKNOWN", "reason": "unsupported source mode"}
    def git(*args):
        return subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.DEVNULL,
                                       timeout=10)
    try:
        sha = git("rev-parse", "HEAD").decode().strip()
        claimed = os.getenv("OLA_RUNTIME_COMMIT")
        if claimed and claimed != sha:
            raise ValueError("runtime SHA declaration differs from Git HEAD")
        entries = git("ls-tree", "-rz", "HEAD", "--", "app", "policies").split(b"\0")
        hashes = {}
        for entry in filter(None, entries):
            meta, name = entry.split(b"\t", 1)
            mode, kind, oid = meta.split()
            path = name.decode()
            if mode not in (b"100644", b"100755") or kind != b"blob":
                raise ValueError("unsupported source file type")
            local = root / path
            if local.is_symlink() or not local.is_file():
                raise ValueError("source file missing or symlinked")
            data = local.read_bytes()
            if data != git("cat-file", "blob", oid.decode()):
                raise ValueError("source bytes differ from committed tree")
            hashes[path] = hashlib.sha256(data).hexdigest()
        if "app/main.py" not in hashes or "policies/nina-review-v1.json" not in hashes:
            raise ValueError("incomplete source boundary")
        for directory in (root / "app", root / "policies"):
            for path in directory.rglob("*"):
                if "__pycache__" in path.parts:
                    continue
                if path.is_symlink():
                    raise ValueError("symlink in source boundary")
                if path.is_file() and str(path.relative_to(root)) not in hashes:
                    raise ValueError("untracked file in source boundary")
        if git("rev-parse", "HEAD").decode().strip() != sha:
            raise ValueError("source changed during capture")
        return {"status": "LOCAL", "sha": sha, "files_digest": digest(hashes),
                "boundary": "git-app-and-policies-on-disk-v1"}
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        return {"status": "UNKNOWN", "reason": str(exc)}


def load_policy():
    raw = POLICY_PATH.read_bytes()
    policy = json.loads(raw)
    if (policy.get("id") != "OLA-NINA-REVIEW-v1" or
        policy.get("operation") != "nina-run" or
        policy.get("execution_authorization") != "registered-capabilities" or
        policy.get("human_scope") != "review-result" or
        policy.get("approval_ttl_seconds") != 900 or
        policy.get("production_allowed") is not False or
        policy.get("allowed_tools") != ["safe_expression", "local_mcp_tool_registry.sha256"]):
        raise ValueError("unsupported policy")
    return policy, hashlib.sha256(raw).hexdigest()


def prepare_binding(tenant_id, requester_id, task, tools):
    source = capture_source()
    if source["status"] != "LOCAL":
        raise ValueError("source binding unavailable: " + source.get("reason", "unknown"))
    policy, policy_digest = load_policy()
    if not isinstance(task, str) or not task.strip() or not isinstance(tools, list):
        raise ValueError("invalid operation parameters")
    if not tools or any(not isinstance(t, str) or t not in policy["allowed_tools"] for t in tools):
        raise ValueError("capability denied by policy")
    return {"tenant_id": tenant_id, "requester_id": requester_id,
            "operation": "nina-run", "parameters_digest": digest({"task": task, "requested_tools": tools}),
            "source": source, "policy_digest": policy_digest,
            "policy_id": policy["id"], "policy_decision": "ALLOW",
            "authorization_kind": "registered-capabilities", "human_scope": policy["human_scope"]}


def validate_review_subject(candidate, tenant_id, requester_id, report_sha256, now=None):
    """Validate persisted report and binding against current local source/policy."""
    from .decision_report_v2 import inspect_decision_report_v2
    report = candidate.get("decision_report_v2")
    binding = candidate.get("execution_binding")
    if not isinstance(report, dict) or inspect_decision_report_v2(report)["integrity"] != "LOCAL":
        raise ValueError("missing or invalid bound report; rerun required")
    if not isinstance(report_sha256, str) or report_sha256 != report["report_sha256"]:
        raise ValueError("report digest mismatch")
    if not isinstance(binding, dict) or binding.get("tenant_id") != tenant_id or binding.get("requester_id") != requester_id:
        raise ValueError("binding identity mismatch")
    policy, pd = load_policy()
    source = capture_source()
    if source.get("status") != "LOCAL" or source != binding.get("source"):
        raise ValueError("source changed or unavailable")
    if (binding.get("operation") != "nina-run" or binding.get("policy_decision") != "ALLOW"
            or binding.get("policy_digest") != pd or binding.get("policy_id") != policy["id"]
            or binding.get("human_scope") != "review-result"):
        raise ValueError("policy binding mismatch")
    if report["bindings"]["source_sha"] != source["sha"] or report["bindings"]["policy_digest"] != pd:
        raise ValueError("report binding mismatch")
    if report["legacy_report"].get("execution_binding") != binding:
        raise ValueError("report does not bind execution context")
    if report["legacy_report"].get("run_id") != candidate.get("run_id"):
        raise ValueError("report run mismatch")
    expires = candidate.get("review_expires_at")
    issued = candidate.get("review_issued_at")
    now = int(time.time()) if now is None else now
    if (type(expires) is not int or type(issued) is not int or
            expires - issued != policy["approval_ttl_seconds"] or not issued <= now < expires):
        raise ValueError("review expired or invalid time window")
    return binding


def review_state(chain, run_id, now=None):
    """Re-evaluate a review at use time; never grant execution permission."""
    from .hashchain import verify_chain
    now = int(time.time()) if now is None else now
    ok, _ = verify_chain(chain)
    if not ok:
        return "BLOCKED", None
    candidate = None
    candidate_previous_hash = None
    approval = None
    approval_hash = None
    revoked = set()
    for row in chain:
        payload = json.loads(row["payload_json"])
        if payload.get("run_id") != run_id:
            continue
        if row["record_type"] == "decision.candidate":
            candidate = payload
            candidate_previous_hash = row["prev_hash"]
        elif row["record_type"] == "human.approval":
            approval, approval_hash = payload, row["record_hash"]
        elif row["record_type"] == "human.approval.revoked":
            revoked.add(payload.get("human_approval_digest"))
    if approval is None or candidate is None:
        return "UNKNOWN", None
    if candidate.get("decision_report_v2", {}).get("bindings", {}).get("evidence_root") != candidate_previous_hash:
        return "BLOCKED", None
    ad = digest(approval)
    if ad in revoked:
        return "REVOKED", ad
    try:
        binding = validate_review_subject(candidate, approval.get("tenant_id"),
            approval.get("requester_id"), approval.get("report_sha256"), now=now)
        if (approval.get("scope") != "review-result" or approval.get("status") != "APPROVED"
                or approval.get("source_sha") != binding["source"]["sha"]
                or approval.get("policy_digest") != binding["policy_digest"]
                or approval.get("parameters_digest") != binding["parameters_digest"]
                or approval.get("expires_at") != candidate["review_expires_at"]
                or type(approval.get("issued_at")) is not int
                or not candidate["review_issued_at"] <= approval["issued_at"] <= now
                or not approval.get("approver_id")
                or approval["approver_id"] == approval["requester_id"]):
            return "BLOCKED", ad
    except (ValueError, OSError, KeyError, TypeError):
        return "BLOCKED", ad
    if chain[-1]["record_hash"] != approval_hash:
        return "STALE", ad
    return "APPROVED", ad
