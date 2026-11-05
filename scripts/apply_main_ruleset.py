#!/usr/bin/env python3
"""Owner-only activation of OLA's protected-main policy.

Default is read-only. Requires gh CLI logged in as repository administrator.
Never handles a private signing key, signs a commit, or approves a PR.
"""
import argparse
import json
import subprocess
import sys
from datetime import datetime

REPO = "krzysztofcieciwa07-ship-it/OLA"
NAME = "ola-production-main-guard-v1"
GITHUB_ACTIONS_INTEGRATION_ID = 15368

# These are the exact successful check-run contexts observed on main SHA
# 64fcf3a1a1b620620555b647faa71fb5e6a109ba. Keep context names exact:
# GitHub does not infer workflow display names from job check names.
CHECKS = (
    "CodeQL / actions",
    "CodeQL / python",
    "continuity",
    "dag-tests",
    "decision-evidence",
    "e2e",
    "evidence-graph",
    "evidence-graph-ubuntu26-compat",
    "final-production",
    "gitleaks",
    "nina-igor-ollama-full-flow",
    "ollama-real-runtime",
    "pr2-focused-tests",
    "product-gate",
    "provenance-gate-final",
    "provenance-mutation",
    "real-parallel-ollama",
    "revenue-surface",
    "runtime-proof",
    "security-image",
    "stress",
    "test",
    "verify",
    "zizmor",
)


def required_check_entries():
    return [
        {"context": name, "integration_id": GITHUB_ACTIONS_INTEGRATION_ID}
        for name in CHECKS
    ]


def policy():
    return {
        "name": NAME,
        "target": "branch",
        "enforcement": "active",
        "bypass_actors": [],
        "conditions": {
            "ref_name": {
                "include": ["refs/heads/main"],
                "exclude": [],
            }
        },
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
                    "required_status_checks": required_check_entries(),
                },
            },
        ],
    }


def validate_check_runs(payload, expected_sha):
    """Fail closed unless every required context passed on the exact main SHA
    and originated from the GitHub Actions integration.
    """
    if not isinstance(payload, dict) or not isinstance(payload.get("check_runs"), list):
        raise RuntimeError("GitHub check-runs response is malformed")
    if not isinstance(expected_sha, str) or len(expected_sha) != 40:
        raise RuntimeError("main must resolve to a full 40-character commit SHA")

    observed = payload["check_runs"]
    missing = []
    blocked = []
    for context in CHECKS:
        matching = [
            item for item in observed
            if item.get("name") == context
            and (item.get("head_sha") in (None, expected_sha))
            and (item.get("app") or {}).get("id") == GITHUB_ACTIONS_INTEGRATION_ID
        ]
        if not matching:
            missing.append(context)
            continue

        # GitHub can return more than one run with the same context. Inspect
        # the newest run, not an older success that hides a newer failure.
        newest = max(
            matching,
            key=lambda item: (
                item.get("completed_at") or "",
                item.get("started_at") or "",
                item.get("id") or 0,
            ),
        )
        if newest.get("status") != "completed" or newest.get("conclusion") != "success":
            blocked.append({
                "context": context,
                "status": newest.get("status"),
                "conclusion": newest.get("conclusion"),
                "run_id": newest.get("id"),
            })

    if missing or blocked:
        raise RuntimeError(
            "main exact-SHA checks are not ready: "
            + json.dumps({"missing": missing, "blocked": blocked}, sort_keys=True)
        )
    return {"sha": expected_sha, "passed_contexts": len(CHECKS)}


def gh(method, path, data=None):
    command = ["gh", "api", "--method", method, path]
    if data is not None:
        command.extend(["--input", "-"])
    done = subprocess.run(
        command,
        input=json.dumps(data) if data is not None else None,
        text=True,
        capture_output=True,
        check=False,
    )
    if done.returncode:
        raise RuntimeError(
            f"GitHub API {method} {path} failed (exit {done.returncode}); "
            "verify repository Administration:write and Checks:read permissions"
        )
    try:
        return json.loads(done.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"GitHub API returned invalid JSON for {method} {path}") from exc


def _rule_map(rules):
    return {item.get("type"): item for item in rules if isinstance(item, dict)}


def verify_ruleset(detail, effective_rules, expected_sha):
    """Verify stored and effective rules; do not trust a successful POST alone."""
    if detail.get("enforcement") != "active":
        raise RuntimeError("ruleset enforcement is not active")
    if detail.get("bypass_actors") != []:
        raise RuntimeError("ruleset unexpectedly has bypass actors")
    refs = detail.get("conditions", {}).get("ref_name", {})
    if refs.get("include") != ["refs/heads/main"] or refs.get("exclude") != []:
        raise RuntimeError("ruleset scope is not exclusively refs/heads/main")

    stored = _rule_map(detail.get("rules", []))
    effective = _rule_map(effective_rules)
    required_types = {
        "deletion",
        "non_fast_forward",
        "required_signatures",
        "pull_request",
        "required_status_checks",
    }
    if not required_types.issubset(stored) or not required_types.issubset(effective):
        raise RuntimeError("one or more required rule types are not effective on main")

    stored_checks = stored["required_status_checks"].get("parameters", {})
    effective_checks = effective["required_status_checks"].get("parameters", {})
    expected_entries = {
        (name, GITHUB_ACTIONS_INTEGRATION_ID) for name in CHECKS
    }

    def entries(parameters):
        return {
            (item.get("context"), item.get("integration_id"))
            for item in parameters.get("required_status_checks", [])
        }

    if entries(stored_checks) != expected_entries:
        raise RuntimeError("stored required status-check contexts differ from the reviewed policy")
    if entries(effective_checks) != expected_entries:
        raise RuntimeError("effective main required status-check contexts differ from the reviewed policy")
    if not stored_checks.get("strict_required_status_checks_policy"):
        raise RuntimeError("strict required status checks are not enabled")

    review = stored["pull_request"].get("parameters", {})
    if (review.get("required_approving_review_count") != 1
            or not review.get("dismiss_stale_reviews_on_push")
            or not review.get("require_last_push_approval")
            or not review.get("required_review_thread_resolution")):
        raise RuntimeError("independent review requirements differ from the reviewed policy")

    if detail.get("target") != "branch":
        raise RuntimeError("ruleset target is not branch")
    return {
        "status": "VERIFIED",
        "ruleset_id": detail.get("id"),
        "main_sha": expected_sha,
        "enforcement": "active",
        "required_contexts": len(CHECKS),
        "integration_id": GITHUB_ACTIONS_INTEGRATION_ID,
    }


def apply():
    branch = gh("GET", f"repos/{REPO}/branches/main")
    if branch.get("name") != "main":
        raise RuntimeError("Target main branch not verified")
    target_sha = (branch.get("commit") or {}).get("sha")
    checks = gh("GET", f"repos/{REPO}/commits/{target_sha}/check-runs?per_page=100")
    check_proof = validate_check_runs(checks, target_sha)

    existing = gh("GET", f"repos/{REPO}/rulesets")
    duplicates = [r for r in existing if r.get("name") == NAME]
    if duplicates:
        raise RuntimeError(
            "Ruleset already exists: inspect and verify it; never create a duplicate"
        )

    created = gh("POST", f"repos/{REPO}/rulesets", policy())
    ruleset_id = created.get("id")
    if not ruleset_id:
        raise RuntimeError("Created response lacked ruleset id; verify manually")

    detail = gh("GET", f"repos/{REPO}/rulesets/{ruleset_id}")
    effective = gh("GET", f"repos/{REPO}/rules/branches/main")
    result = verify_ruleset(detail, effective, target_sha)
    result["check_preflight"] = check_proof
    print(json.dumps(result, sort_keys=True))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true", help="Requires owner/admin authorization")
    options = parser.parse_args()
    if not options.apply:
        print(json.dumps({
            "status": "DRY_RUN_ONLY",
            "repository": REPO,
            "policy": policy(),
        }, indent=2))
        return 0
    try:
        apply()
    except (RuntimeError, OSError, ValueError) as exc:
        print(json.dumps({"status": "BLOCKED", "error": str(exc)}), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
