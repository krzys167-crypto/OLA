#!/usr/bin/env python3
"""OLA project-continuity v1: fail-closed task registry and duplicate-work guard.

Offline standard-library CLI. A syntactically valid evidence reference is NOT an
independent attestation: operators must check the referenced CI run and SHA.
"""
import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from urllib.parse import urlparse

STATES = {"TODO", "IN_PROGRESS", "BLOCKED", "DONE"}
VERIFICATIONS = {"UNVERIFIED", "PARTIAL", "BLOCKED", "VERIFIED"}
SHA_RE = re.compile(r"[0-9a-f]{40}")
HEX_RE = re.compile(r"[0-9a-f]{64}")


class InvalidLedger(ValueError):
    pass


def require(predicate, message):
    if not predicate:
        raise InvalidLedger(message)


def validate(registry):
    require(type(registry) is dict and registry.get("schema_version") == 1,
            "unknown schema_version (requires 1)")
    require(registry.get("project") == "OLA-DI-OS", "unexpected project")
    require(type(registry.get("bootstrap_inventory_incomplete")) is bool,
            "inventory-completeness flag missing")
    tasks = registry.get("tasks")
    require(type(tasks) is list, "tasks must be a list")
    seen = set()
    for t in tasks:
        require(type(t) is dict and type(t.get("id")) is str and t["id"], "task missing id")
        require(t["id"] not in seen, "duplicate task id")
        seen.add(t["id"])
        require(type(t.get("title")) is str and t["title"].strip(), "task missing title")
        require(type(t.get("priority")) is int and 0 <= t["priority"] <= 9,
                "priority must be 0..9")
        require(t.get("state") in STATES, "invalid task state")
        require(t.get("verification") in VERIFICATIONS, "invalid verification")
        require(type(t.get("watched_files")) is dict, "missing watched_files")
        require(t.get("proof") is None or type(t.get("proof")) is dict, "invalid proof")
        if t["state"] == "DONE" or t["verification"] == "VERIFIED":
            require(t["state"] == "DONE" and t["verification"] == "VERIFIED",
                    "DONE and VERIFIED must occur together")
            p = t["proof"]
            require(type(p) is dict, "VERIFIED missing proof")
            require(type(p.get("source_commit")) is str and SHA_RE.fullmatch(p["source_commit"]),
                    "VERIFIED missing valid source_commit")
            require(valid_ci_url(p.get("verification_url")),
                    "VERIFIED missing valid CI URL")
            require(bool(t["watched_files"]), "VERIFIED missing watched_files")
            require(all(type(k) is str and type(v) is str and HEX_RE.fullmatch(v)
                        for k, v in t["watched_files"].items()),
                    "invalid watched_files digest")
    return registry


def valid_ci_url(value):
    if not isinstance(value, str):
        return False
    parsed = urlparse(value)
    return parsed.scheme == "https" and parsed.netloc == "github.com" and bool(
        re.fullmatch(r"/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/runs/[0-9]+/?", parsed.path)
    ) and not parsed.query and not parsed.fragment


def load(path):
    try:
        return validate(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError) as e:
        raise InvalidLedger(f"cannot read registry: {e}") from e


def save(path, data):
    validate(data)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Writes replace a complete JSON snapshot; Git commit history is the durable audit log.
    temp = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent,
                                         prefix=".registry-", delete=False) as f:
            temp = Path(f.name)
            json.dump(data, f, indent=2, ensure_ascii=False, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
    finally:
        if temp is not None and temp.exists():
            temp.unlink()


def find_task(registry, task_id):
    for t in registry["tasks"]:
        if t["id"] == task_id:
            return t
    raise InvalidLedger(f"unknown task: {task_id}")


def digest_path(root, user_path):
    path = Path(user_path)
    require(not path.is_absolute() and all(part not in ("..", "") for part in path.parts),
            "watched path must be inside project")
    target = root / path
    require(target.resolve().is_relative_to(root.resolve()), "path traversal")
    require(target.is_file() and not target.is_symlink(), "watched file missing or symlink")
    return hashlib.sha256(target.read_bytes()).hexdigest()


def decision(t, root):
    if t["state"] == "BLOCKED" or t["verification"] == "BLOCKED":
        return "BLOCKED"
    if t["state"] == "DONE" and t["verification"] == "VERIFIED":
        for path, expected in t["watched_files"].items():
            try:
                if digest_path(root, path) != expected:
                    return "REVERIFY"
            except InvalidLedger:
                return "REVERIFY"
        return "SKIP"
    return "RUN"


def emit(value):
    print(json.dumps(value, sort_keys=True, ensure_ascii=False))


def command(args):
    root = Path(args.root).resolve()
    registry_path = Path(args.registry).resolve() if args.registry else root / ".ola/continuity/registry.json"
    data = load(registry_path)
    if args.cmd == "status":
        emit({"project": data["project"], "bootstrap_inventory_incomplete": data["bootstrap_inventory_incomplete"],
              "tasks": [{"id": t["id"], "title": t["title"], "state": t["state"],
                         "verification": t["verification"], "priority": t["priority"],
                         "decision": decision(t, root)} for t in data["tasks"]]})
    elif args.cmd == "check":
        task = find_task(data, args.task_id)
        emit({"task_id": task["id"], "decision": decision(task, root),
              "state": task["state"], "verification": task["verification"]})
    elif args.cmd == "next":
        eligible = [(t, decision(t, root)) for t in data["tasks"]]
        eligible = [(t, d) for t, d in eligible if d in ("RUN", "REVERIFY")]
        if eligible:
            t, d = sorted(eligible, key=lambda item:
                          (item[0]["priority"], item[0]["state"] != "IN_PROGRESS", item[0]["id"]))[0]
            emit({"task_id": t["id"], "title": t["title"], "decision": d,
                  "inventory_incomplete": data["bootstrap_inventory_incomplete"]})
        else:
            emit({"decision": "NONE", "inventory_incomplete": data["bootstrap_inventory_incomplete"]})
    elif args.cmd == "add":
        require(not any(t["id"] == args.task_id for t in data["tasks"]), "task already exists")
        data["tasks"].append({"id": args.task_id, "title": args.title,
                              "priority": args.priority, "state": "TODO",
                              "verification": "UNVERIFIED", "proof": None, "watched_files": {}})
        save(registry_path, data)
        emit({"task_id": args.task_id, "updated": True})
    elif args.cmd == "set":
        task = find_task(data, args.task_id)
        new = copy.deepcopy(task)
        if args.state:
            new["state"] = args.state
        if args.verification:
            new["verification"] = args.verification
        if task["state"] == "DONE" and (new["state"], new["verification"]) != ("DONE", "VERIFIED"):
            require(args.reopen_reason is not None and args.reopen_reason.strip(),
                    "cannot downgrade verified task without --reopen-reason")
        if new["state"] == "DONE" and new["verification"] == "VERIFIED":
            if args.source_commit or args.verification_url or args.watch:
                require(args.source_commit and args.verification_url and args.watch,
                        "full source commit, CI URL, and watched files required")
                new["proof"] = {"source_commit": args.source_commit,
                                "verification_url": args.verification_url,
                                "recorded_at": datetime.now(timezone.utc).isoformat()}
                new["watched_files"] = {p: digest_path(root, p) for p in args.watch}
        elif args.reopen_reason:
            new["proof"] = None
            new["watched_files"] = {}
            new["reopen_reason"] = args.reopen_reason
        task.update(new)
        save(registry_path, data)
        emit({"task_id": task["id"], "updated": True, "decision": decision(task, root)})


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", default=str(Path(__file__).resolve().parent.parent))
    p.add_argument("--registry")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status")
    sub.add_parser("next")
    check = sub.add_parser("check")
    check.add_argument("task_id")
    add = sub.add_parser("add")
    add.add_argument("task_id")
    add.add_argument("--title", required=True)
    add.add_argument("--priority", type=int, default=5)
    setp = sub.add_parser("set")
    setp.add_argument("task_id")
    setp.add_argument("--state", choices=sorted(STATES))
    setp.add_argument("--verification", choices=sorted(VERIFICATIONS))
    setp.add_argument("--source-commit")
    setp.add_argument("--verification-url")
    setp.add_argument("--watch", action="append")
    setp.add_argument("--reopen-reason")
    args = p.parse_args()
    try:
        command(args)
    except (InvalidLedger, ValueError) as e:
        print(f"BLOCKED: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
