#!/usr/bin/env python3
"""Owner-only activation of OLA's protected-main policy.

Default is read-only. Requires gh CLI logged in as repository administrator.
Never handles a private signing key, signs a commit, or approves a PR.
"""
import argparse
import json
import subprocess
import sys

REPO = "krzysztofcieciwa07-ship-it/OLA"
NAME = "ola-production-main-guard-v1"
CHECKS = (
    "CodeQL",                 # GitHub Advanced Security, not merely OLA CodeQL workflow
    "CodeQL / python",
    "gitleaks",
    "security-image",
    "dag-tests",
    "e2e",
    "product-gate",
    "final-production",
)


def policy():
    return {
        "name": NAME,
        "target": "branch",
        "enforcement": "active",
        "bypass_actors": [],
        "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
        "rules": [
            {"type": "deletion"},
            {"type": "non_fast_forward"},
            {"type": "required_signatures"},
            {
                "type": "pull_request",
                "parameters": {
                    "allowed_merge_methods": ["merge", "squash"],
                    "dismiss_stale_reviews_on_push": True,
                    "require_code_owner_review": False,
                    "require_last_push_approval": True,
                    "required_approving_review_count": 1,
                    "required_review_thread_resolution": True,
                },
            },
            {
                "type": "required_status_checks",
                "parameters": {
                    "strict_required_status_checks_policy": True,
                    "do_not_enforce_on_create": False,
                    "required_status_checks": [{"context": name} for name in CHECKS],
                },
            },
        ],
    }


def gh(method, path, data=None):
    command = ["gh", "api", "--method", method, path]
    if data is not None:
        command.extend(["--input", "-"])
    done = subprocess.run(command, input=json.dumps(data) if data is not None else None,
                          text=True, capture_output=True, check=False)
    if done.returncode:
        raise RuntimeError(f"GitHub API {method} {path} failed (exit {done.returncode})"
                           "; verify repository Administration:write permission")
    return json.loads(done.stdout)


def apply():
    existing = gh("GET", f"repos/{REPO}/rulesets")
    duplicates = [r for r in existing if r.get("name") == NAME]
    if duplicates:
        raise RuntimeError("Ruleset already exists: inspect and verify it; never create duplicate")
    branch = gh("GET", f"repos/{REPO}/branches/main")
    if branch.get("name") != "main":
        raise RuntimeError("Target main branch not verified")
    created = gh("POST", f"repos/{REPO}/rulesets", policy())
    rid = created.get("id")
    if not rid:
        raise RuntimeError("Created response lacked ruleset id; verify manually")
    detail = gh("GET", f"repos/{REPO}/rulesets/{rid}")
    active = gh("GET", f"repos/{REPO}/rules/branches/main")
    got = {r.get("type") for r in detail.get("rules", [])}
    applied = {r.get("type") for r in active}
    required = {r["type"] for r in policy()["rules"]}
    if (detail.get("enforcement") != "active" or
            not required.issubset(got) or not required.issubset(applied)):
        raise RuntimeError(f"Ruleset {rid} exists but required rules are NOT VERIFIED")
    print(json.dumps({"status": "VERIFIED", "ruleset_id": rid,
                      "main_sha": branch.get("commit", {}).get("sha"),
                      "enforcement": "active", "rules": sorted(required)}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true", help="Requires explicit authorization")
    options = parser.parse_args()
    if not options.apply:
        print(json.dumps({"status": "DRY_RUN_ONLY", "repository": REPO, "policy": policy()}, indent=2))
        return 0
    try:
        apply()
    except (RuntimeError, OSError, ValueError) as exc:
        print(json.dumps({"status": "BLOCKED", "error": str(exc)}), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
