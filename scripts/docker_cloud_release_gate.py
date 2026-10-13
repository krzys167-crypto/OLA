#!/usr/bin/env python3
"""Fail-closed OLA source, approval and evidence gate for Docker Hub distribution.

This job publishes only an immutable image; it does NOT authorize production
deployment, customer delivery, or LIVE payment.
"""
from __future__ import annotations
import argparse
import json
import os
import re
import sys
import urllib.request
from pathlib import Path
from typing import Any

SHA = re.compile(r"^[0-9a-f]{40}$")
FPR = re.compile(r"^(?:[A-F0-9]{40}|[A-F0-9]{64})$")
REQUIRED_RULE_TYPES = {"required_signatures", "required_status_checks", "non_fast_forward", "deletion"}


class Denied(Exception):
    pass


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise Denied(reason)


def parse_allowlist(value: str) -> set[str]:
    fingerprints = [s.upper() for s in re.split(r"[,;\s]+", value.strip()) if s]
    require(bool(fingerprints) and all(FPR.fullmatch(s) for s in fingerprints),
            "approved GPG signer fingerprint allowlist missing or invalid")
    return set(fingerprints)


def validate_release_request(source_sha: str, requested_sha: str, enabled: str,
                             allowed_fprs: str, docker_user: str, git_ref: str) -> bool:
    require(bool(SHA.fullmatch(source_sha or "")), "invalid source SHA")
    require(source_sha == requested_sha, "requested release SHA != workflow main SHA")
    require(git_ref == "refs/heads/main", "release restricted to main")
    require(enabled == "true", "release feature switch is not enabled")
    require(docker_user == "krzysztof1678", "Docker Hub account differs from reviewed image owner")
    parse_allowlist(allowed_fprs)
    return True


def _applies_to_main(rule: dict) -> bool:
    if rule.get("target") != "branch" or rule.get("enforcement") != "active":
        return False
    include = ((rule.get("conditions") or {}).get("ref_name") or {}).get("include") or []
    exclude = ((rule.get("conditions") or {}).get("ref_name") or {}).get("exclude") or []
    return ("~DEFAULT_BRANCH" in include or "refs/heads/main" in include) and not (
        "~DEFAULT_BRANCH" in exclude or "refs/heads/main" in exclude)


def validate_release_policies(branch: dict, rulesets: list[dict], environment: dict,
                              commit: dict, source_sha: str) -> bool:
    require(bool(branch.get("protected")), "main branch protection is inactive")
    require((branch.get("commit") or {}).get("sha") == source_sha, "main SHA drift")
    applicable = [x for x in rulesets if _applies_to_main(x)]
    require(bool(applicable), "no active main ruleset")
    require(all(not x.get("bypass_actors") for x in applicable), "ruleset permits release bypass")
    effective = {r.get("type") for x in applicable for r in (x.get("rules") or [])}
    require(REQUIRED_RULE_TYPES <= effective,
            "missing required main rules (GPG/checks/non-fast-forward/deletion)")
    require(environment.get("name") == "production", "incorrect deployment environment")
    policy = environment.get("deployment_branch_policy") or {}
    require(policy.get("protected_branches") is True, "environment allows unprotected branches")
    reviewers = [x for x in environment.get("protection_rules") or []
                 if x.get("type") == "required_reviewers" and
                 x.get("prevent_self_review") is True and (x.get("reviewers") or [])]
    require(bool(reviewers), "production requires an independent protected-environment reviewer")
    verification = (commit.get("commit") or {}).get("verification") or {}
    require(commit.get("sha") == source_sha and verification.get("verified") is True and
            verification.get("reason") == "valid", "source commit is unsigned or not GitHub VERIFIED")
    return True


def choose_final_gate_run(runs: list[dict], source_sha: str) -> int:
    eligible = [x for x in runs if x.get("head_sha") == source_sha
                and x.get("status") == "completed" and x.get("conclusion") == "success"
                and x.get("event") == "push" and x.get("head_branch") == "main"
                and type(x.get("id")) is int and x["id"] > 0]
    require(bool(eligible), "no successful source-bound FINAL PRODUCTION GATE main-push run")
    return max(x["id"] for x in eligible)


def validate_release_manifest(manifest: dict, signer: dict, source_sha: str,
                              allowed_fprs: str) -> bool:
    allowed = parse_allowlist(allowed_fprs)
    for key, expected in {
        "schema": "ola-production-evidence-v1",
        "commit": source_sha,
        "final_status": "ATTESTED_PENDING_HUMAN",
        "human_gate": "PENDING",
        "go_no_go": "NO-GO",
        "production_deployment": "NOT_PERFORMED",
        "commit_signature_gate": "GITHUB_COMMIT_VERIFIED",
    }.items():
        require(manifest.get(key) == expected, f"manifest mismatch: {key}")
    require(signer.get("status") == "VERIFIED" and signer.get("head_sha") == source_sha
            and signer.get("production_go") == "NO-GO", "invalid independent main signer proof")
    commits = signer.get("commits")
    require(isinstance(commits, list) and len(commits) > 0 and
            signer.get("verified_count") == len(commits) and
            type(signer.get("owner_signed_count")) is int and signer["owner_signed_count"] > 0,
            "missing owner-signed release provenance")
    owner_count = 0
    for commit in commits:
        kind = commit.get("classification")
        require(kind in ("OWNER_GPG_VERIFIED", "GITHUB_SIGNED_MERGE"), "unknown signer classification")
        if kind == "OWNER_GPG_VERIFIED":
            require(commit.get("signer", "").upper() in allowed, "owner signer not on approved allowlist")
            owner_count += 1
    require(owner_count == signer["owner_signed_count"], "owner signature count mismatch")
    require(commits[-1].get("sha") == source_sha, "signer proof not bound to release head")
    return True


def api(repo: str, token: str, path: str) -> Any:
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repo}/{path}",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "OLA-docker-release-policy"})
    with urllib.request.urlopen(request, timeout=25) as response:
        return json.load(response)


def preflight() -> int:
    source_sha = os.getenv("GITHUB_SHA", "")
    allowed = os.getenv("OLA_ALLOWED_SIGNER_FPRS", "")
    validate_release_request(source_sha, os.getenv("RELEASE_SHA", ""),
                             os.getenv("OLA_RELEASE_ENABLED", ""), allowed,
                             os.getenv("DOCKER_USER", ""), os.getenv("GITHUB_REF", ""))
    repo, token = os.getenv("GITHUB_REPOSITORY", ""), os.getenv("GH_TOKEN", "")
    require(bool(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo)) and bool(token),
            "missing repository identity or restricted read-only GitHub token")
    branch = api(repo, token, "branches/main")
    rules = api(repo, token, "rulesets?includes_parents=true&per_page=100")
    require(isinstance(rules, list) and len(rules) < 100, "missing or unbounded rulesets")
    detailed = [api(repo, token, f"rulesets/{r['id']}") for r in rules
                if r.get("target") == "branch" and r.get("enforcement") == "active"]
    environment = api(repo, token, "environments/production")
    commit = api(repo, token, f"commits/{source_sha}")
    validate_release_policies(branch, detailed, environment, commit, source_sha)
    runs = api(repo, token,
               f"actions/workflows/final-production-gate.yml/runs?event=push&head_sha={source_sha}&per_page=100")
    require(isinstance(runs, dict) and isinstance(runs.get("workflow_runs"), list),
            "unable to list production gate runs")
    run_id = choose_final_gate_run(runs["workflow_runs"], source_sha)
    output = os.getenv("GITHUB_OUTPUT", "")
    require(bool(output), "GitHub output destination missing")
    with open(output, "a", encoding="utf-8") as stream:
        stream.write(f"gate_run_id={run_id}\n")
    print(f"POLICY_PREFLIGHT=PASS source={source_sha} final_gate_run={run_id}")
    return 0


def verify_artifact(path: Path) -> int:
    source_sha = os.getenv("GITHUB_SHA", "")
    validate_release_manifest(
        json.loads((path / "production-manifest.json").read_text(encoding="utf-8")),
        json.loads((path / "main-signature-result.json").read_text(encoding="utf-8")),
        source_sha, os.getenv("OLA_ALLOWED_SIGNER_FPRS", ""))
    print(f"RELEASE_ARTIFACT_POLICY=PASS source={source_sha} human_gate=GITHUB_PRODUCTION_ENVIRONMENT")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("preflight", "artifact"))
    parser.add_argument("--artifact-dir", type=Path, default=Path("release-evidence"))
    opts = parser.parse_args()
    try:
        return preflight() if opts.mode == "preflight" else verify_artifact(opts.artifact_dir)
    except (Denied, OSError, ValueError, KeyError, TypeError) as err:
        print(f"DOCKER_RELEASE=BLOCKED reason={err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
