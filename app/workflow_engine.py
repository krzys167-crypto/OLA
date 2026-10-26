"""Bounded DAG executor for NINA; deliberately does not grant a VERIFIED decision.

Only independent ready nodes run in parallel. Scheduling and evidence event
emission stay in the coordinator, never in worker threads.
"""
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass
import hashlib
import json
import math
import re
import time
import uuid


class WorkflowPlanError(ValueError):
    pass


@dataclass(frozen=True)
class WorkflowNode:
    id: str
    tool: str
    task: str
    needs: tuple[str, ...]


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


def validate_plan(data, *, allowed_tools, max_nodes=16):
    """Reject ambiguous, cyclic, oversized or non-allowlisted model output."""
    if not isinstance(data, dict) or set(data) != {"nodes"}:
        raise WorkflowPlanError("plan must contain only nodes")
    raw = data["nodes"]
    if not isinstance(raw, list) or not 1 <= len(raw) <= max_nodes:
        raise WorkflowPlanError("node count outside policy")
    nodes = []
    seen = set()
    for item in raw:
        if not isinstance(item, dict) or set(item) != {"id", "tool", "task", "needs"}:
            raise WorkflowPlanError("invalid node fields")
        node_id, tool, task, needs = (item[k] for k in ("id", "tool", "task", "needs"))
        if not isinstance(node_id, str) or not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_-]{0,39}", node_id):
            raise WorkflowPlanError("invalid node id")
        if node_id in seen:
            raise WorkflowPlanError("duplicate node")
        if not isinstance(tool, str) or tool not in allowed_tools:
            raise WorkflowPlanError("tool not permitted")
        if not isinstance(task, str) or not task.strip() or len(task) > 1000:
            raise WorkflowPlanError("invalid node task")
        if not isinstance(needs, list) or len(needs) != len(set(str(x) for x in needs)) or not all(isinstance(x, str) for x in needs):
            raise WorkflowPlanError("invalid dependencies")
        if node_id in needs:
            raise WorkflowPlanError("self-dependency")
        seen.add(node_id)
        nodes.append(WorkflowNode(node_id, tool, task.strip(), tuple(needs)))
    if any(dep not in seen for node in nodes for dep in node.needs):
        raise WorkflowPlanError("unknown dependency")
    remaining = {node.id: set(node.needs) for node in nodes}
    processed = set()
    while remaining:
        ready = {key for key, deps in remaining.items() if deps <= processed}
        if not ready:
            raise WorkflowPlanError("cyclic dependencies")
        processed.update(ready)
        for key in ready:
            del remaining[key]
    return tuple(nodes)


class WorkflowEngine:
    def __init__(self, *, max_workers=4, deadline_seconds=300):
        if not isinstance(max_workers, int) or isinstance(max_workers, bool) or not 1 <= max_workers <= 8:
            raise ValueError("worker count outside policy")
        if (isinstance(deadline_seconds, bool) or not isinstance(deadline_seconds, (int, float))
                or not math.isfinite(deadline_seconds) or not 0 < deadline_seconds <= 3600):
            raise ValueError("workflow deadline outside policy")
        self.max_workers = max_workers
        self.deadline_seconds = deadline_seconds

    def run(self, nodes, execute, record=None, *, run_id=None):
        """Execute a previously validated plan; record is a synchronous event sink.

        A persistence failure propagates instead of returning COMPLETED.
        """
        if not nodes or not all(isinstance(node, WorkflowNode) for node in nodes):
            raise WorkflowPlanError("validated nodes required")
        # Revalidate, even when the caller supplies WorkflowNode instances.
        nodes = validate_plan({"nodes": [dict(id=n.id, tool=n.tool, task=n.task, needs=list(n.needs)) for n in nodes]},
                              allowed_tools={n.tool for n in nodes})
        record = record or (lambda event: None)
        run_id = run_id or str(uuid.uuid4())
        plan = [dict(id=n.id, tool=n.tool, task=n.task, needs=list(n.needs)) for n in nodes]
        record({"event": "workflow.planned", "run_id": run_id, "plan_digest": _digest(plan), "nodes": plan})
        pending = {n.id: n for n in nodes}
        results = {}
        failures = {}
        running = {}
        deadline = time.monotonic() + self.deadline_seconds
        timed_out = False
        def measured_execution(node, deps):
            started = time.perf_counter_ns()
            value = execute(node, deps)
            finished = time.perf_counter_ns()
            return value, started, finished

        with ThreadPoolExecutor(max_workers=self.max_workers, thread_name_prefix="ola-nina") as pool:
            while pending or running:
                if time.monotonic() >= deadline:
                    timed_out = True
                    for future, node in list(running.items()):
                        future.cancel()  # Only cancels tasks not yet started.
                        failures[node.id] = "TimeoutError"
                        record({"event": "task.failed", "run_id": run_id,
                                "node_id": node.id, "error_class": "TimeoutError"})
                    running.clear()
                    break
                if not failures:
                    for node_id, node in list(pending.items()):
                        if len(running) >= self.max_workers:
                            break
                        if not set(node.needs) <= results.keys():
                            continue
                        deps = {dep: results[dep] for dep in node.needs}
                        record({"event": "task.started", "run_id": run_id, "node_id": node_id,
                                "input_digest": _digest({"task": node.task, "deps": deps})})
                        running[pool.submit(measured_execution, node, deps)] = node
                        del pending[node_id]
                if not running:
                    break
                done, _ = wait(running, timeout=max(0, deadline - time.monotonic()),
                               return_when=FIRST_COMPLETED)
                if not done:
                    timed_out = True
                    for future, node in list(running.items()):
                        future.cancel()
                        failures[node.id] = "TimeoutError"
                        record({"event": "task.failed", "run_id": run_id,
                                "node_id": node.id, "error_class": "TimeoutError"})
                    running.clear()
                    break
                for future in done:
                    node = running.pop(future)
                    try:
                        value, started, finished = future.result()
                        serialized = json.dumps(value, ensure_ascii=False, sort_keys=True)
                        if len(serialized.encode()) > 8192:
                            raise ValueError("output exceeds policy limit")
                        results[node.id] = value
                        record({"event": "task.completed", "run_id": run_id, "node_id": node.id,
                                "output_digest": _digest(value), "output": value,
                                "worker_started_ns": started, "worker_finished_ns": finished})
                    except Exception as exc:
                        failures[node.id] = type(exc).__name__
                        record({"event": "task.failed", "run_id": run_id, "node_id": node.id,
                                "error_class": type(exc).__name__})
        # Python cannot forcibly stop a running worker; the pool waits for
        # in-flight calls to settle before publishing any terminal result.
        # Expired workflows must never schedule dependants or claim VERIFIED.
        if timed_out or time.monotonic() > deadline:
            failures.setdefault("workflow_deadline", "TimeoutError")
        status = "BLOCK" if failures or pending else "COMPLETED_UNVERIFIED"
        record({"event": "workflow.failed" if status == "BLOCK" else "workflow.completed",
                "run_id": run_id, "status": status, "completed": sorted(results),
                "failed": failures, "skipped": sorted(pending)})
        return {"run_id": run_id, "status": status, "results": results,
                "failed": failures, "skipped": sorted(pending), "plan_digest": _digest(plan)}
