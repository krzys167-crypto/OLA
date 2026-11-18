"""Dedicated dispatcher for OLA's read-only Blogger metadata capability."""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from typing import Any

from .blogger_adapter import BloggerAdapterError, get_blog_metadata
from .hashchain import verify_chain
from .igor import IgorVerifier
from .nina import NinaOrchestrator, NinaTask
from .pipeline_bridge import append_evidence, load_chain

TOOL_NAME = "blogger.read_metadata"
START = "blogger.execution.started"
RESULT = "blogger.metadata.result"
END = "blogger.execution.ended"
BLOG_ID_RE = re.compile(r"^[0-9]{1,32}$")


def _digest_result(result: dict[str, Any]) -> str:
    body = {key: value for key, value in result.items() if key != "result_sha256"}
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode()).hexdigest()


def verify_blogger_evidence(
    records: list[dict], run_id: str, blog_id: str, expected_tenant_id: str
) -> dict:
    """Verify this capability run through IGOR and Blogger-specific semantic checks.

    IGOR's capability verifier validates the tenant hash chain and exact run
    event contract without fabricating LLM/provider provenance.
    """
    if not isinstance(expected_tenant_id, str) or not expected_tenant_id:
        return {
            "status": "BLOCK",
            "reason": "invalid expected tenant",
            "checks": {"tenant_binding": False},
        }

    igor = IgorVerifier().verify_capability_records(
        records,
        expected_tenant_id=expected_tenant_id,
        expected_run_id=run_id,
        expected_record_types=(START, RESULT, END),
        expected_bindings={"blog_id": blog_id},
    )
    chain_ok, chain_reason = verify_chain(records)
    if not chain_ok:
        return {
            "status": "BLOCK",
            "reason": chain_reason,
            "checks": {"chain": False, "igor_capability": False},
        }

    scoped = []
    for row in records:
        try:
            payload = json.loads(row["payload_json"])
        except (KeyError, TypeError, ValueError):
            continue
        if isinstance(payload, dict) and payload.get("run_id") == run_id:
            scoped.append((row, payload))

    if [row.get("record_type") for row, _ in scoped] != [START, RESULT, END]:
        return {
            "status": "UNKNOWN",
            "reason": "missing, duplicate, or reordered Blogger events for this run",
            "checks": {
                "chain": True,
                "igor_capability": igor.status == "VERIFIED",
                "event_order": False,
            },
        }

    start, result_event, end = (item[1] for item in scoped)
    result = result_event.get("result")
    checks = {
        "chain": True,
        "igor_capability": igor.status == "VERIFIED",
        "event_order": True,
        "tenant_binding": all(
            row.get("tenant_id") == expected_tenant_id for row, _ in scoped
        ),
        "blog_id_binding": all(
            payload.get("blog_id") == blog_id
            for payload in (start, result_event, end)
        ),
        "run_binding": all(
            payload.get("run_id") == run_id
            for payload in (start, result_event, end)
        ),
        "tool_binding": start.get("tool") == TOOL_NAME,
        "terminal_state": end.get("status") == "REVIEW_REQUIRED",
        "operation_binding": (
            result_event.get("operation") == "blogs.get"
            and isinstance(result, dict)
            and result.get("operation") == "blogs.get"
        ),
        "result_identity": (
            isinstance(result, dict)
            and result.get("success") is True
            and result.get("verified") is True
            and result.get("blog_id") == blog_id
            and isinstance(result.get("blog_url"), str)
            and result["blog_url"].startswith("https://")
        ),
        "result_digest": (
            isinstance(result, dict)
            and result.get("result_sha256") == _digest_result(result)
        ),
    }
    if not all(checks.values()):
        return {
            "status": "BLOCK",
            "reason": (
                igor.reason
                if igor.status != "VERIFIED"
                else "Blogger evidence semantic verification failed"
            ),
            "checks": checks,
        }

    return {
        "status": "VERIFIED",
        "reason": (
            "IGOR capability evidence and Blogger semantic checks passed; "
            "Google authorship is not cryptographically proven"
        ),
        "checks": checks,
        "evidence_ids": list(igor.evidence_ids),
        "human_gate": "REVIEW_REQUIRED",
    }


def run_blogger_metadata(
    tenant_id: str, blog_id: str, *, adapter=get_blog_metadata
) -> dict:
    if not isinstance(blog_id, str) or not BLOG_ID_RE.fullmatch(blog_id):
        return {"status": "BLOCK", "reason": "INVALID_BLOG_ID", "human_gate": "BLOCK"}

    task = NinaTask.create(
        tenant_id,
        f"Read Blogger metadata for blog {blog_id}",
        [TOOL_NAME],
    )
    # Use NINA's central allow-list; never extend the registry inside a dispatcher.
    plan = NinaOrchestrator().plan(task)
    if plan.status != "ALLOW":
        return {"status": "BLOCK", "reason": plan.reason, "human_gate": "BLOCK"}

    run_id = str(uuid.uuid4())
    append_evidence(
        tenant_id,
        START,
        {"run_id": run_id, "blog_id": blog_id, "tool": TOOL_NAME},
    )
    try:
        data = adapter(blog_id)
        if (
            not isinstance(data, dict)
            or data.get("success") is not True
            or data.get("blog_id") != blog_id
            or data.get("operation") != "blogs.get"
        ):
            raise BloggerAdapterError("ADAPTER_RESULT_INVALID")

        append_evidence(
            tenant_id,
            RESULT,
            {
                "run_id": run_id,
                "blog_id": blog_id,
                "operation": "blogs.get",
                "result": data,
            },
        )
        append_evidence(
            tenant_id,
            END,
            {"run_id": run_id, "blog_id": blog_id, "status": "REVIEW_REQUIRED"},
        )
        verification = verify_blogger_evidence(
            load_chain(tenant_id), run_id, blog_id, tenant_id
        )
        if verification["status"] != "VERIFIED":
            return {
                "status": verification["status"],
                "run_id": run_id,
                "blog_id": blog_id,
                "verification": verification,
                "human_gate": "BLOCK",
                "execution": "NOT_PERFORMED",
            }
        return {
            "status": "REVIEW_REQUIRED",
            "run_id": run_id,
            "blog_id": blog_id,
            "result": data,
            "verification": verification,
            "human_gate": "REVIEW_REQUIRED",
            "execution": "NOT_PERFORMED",
        }
    except BloggerAdapterError as exc:
        append_evidence(
            tenant_id,
            END,
            {
                "run_id": run_id,
                "blog_id": blog_id,
                "status": "BLOCK",
                "error": exc.code,
            },
        )
        return {
            "status": "BLOCK",
            "run_id": run_id,
            "blog_id": blog_id,
            "reason": exc.code,
            "human_gate": "BLOCK",
            "execution": "NOT_PERFORMED",
        }
    except Exception:
        # Do not expose upstream exception text, credentials, or database details.
        append_evidence(
            tenant_id,
            END,
            {
                "run_id": run_id,
                "blog_id": blog_id,
                "status": "BLOCK",
                "error": "INTERNAL_ERROR",
            },
        )
        return {
            "status": "BLOCK",
            "run_id": run_id,
            "blog_id": blog_id,
            "reason": "INTERNAL_ERROR",
            "human_gate": "BLOCK",
            "execution": "NOT_PERFORMED",
        }
