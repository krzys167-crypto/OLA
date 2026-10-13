"""Behavioral contract tests for fail-closed Docker registry publication."""
import unittest
from scripts.docker_cloud_release_gate import (
    Denied, validate_release_request, validate_release_policies,
    choose_final_gate_run, validate_release_manifest,
)
SHA = "a" * 40
FPR = "B" * 40


def valid_rules():
    return [{"id": 7, "enforcement": "active", "target": "branch", "bypass_actors": [],
             "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
             "rules": [{"type": x} for x in (
                 "required_signatures", "required_status_checks", "non_fast_forward", "deletion")]}]


def valid_env():
    return {"name": "production",
            "deployment_branch_policy": {"protected_branches": True},
            "protection_rules": [{"type": "required_reviewers",
                                  "prevent_self_review": True,
                                  "reviewers": [{"type": "User", "reviewer": {"login": "reviewer"}}]}]}


def valid_commit():
    return {"sha": SHA, "commit": {"verification": {"verified": True, "reason": "valid"}}}


class DockerCloudReleaseGateTests(unittest.TestCase):
    def test_happy_path_only_for_signed_protected_reviewed_main(self):
        self.assertTrue(validate_release_request(SHA, SHA, "true", FPR, "krzysztof1678", "refs/heads/main"))
        self.assertTrue(validate_release_policies(
            {"protected": True, "commit": {"sha": SHA}},
            valid_rules(), valid_env(), valid_commit(), SHA))

    def test_source_drift_denied(self):
        with self.assertRaises(Denied):
            validate_release_request(SHA, "c" * 40, "true", FPR, "krzysztof1678", "refs/heads/main")

    def test_absent_allowlist_denied(self):
        with self.assertRaises(Denied):
            validate_release_request(SHA, SHA, "true", "", "krzysztof1678", "refs/heads/main")

    def test_wrong_docker_user_or_disabled_switch_denied(self):
        for user, enabled in [("somebodyelse", "true"), ("krzysztof1678", "false")]:
            with self.subTest(user=user, enabled=enabled), self.assertRaises(Denied):
                validate_release_request(SHA, SHA, enabled, FPR, user, "refs/heads/main")

    def test_unprotected_main_denied(self):
        with self.assertRaises(Denied):
            validate_release_policies(
                {"protected": False, "commit": {"sha": SHA}},
                valid_rules(), valid_env(), valid_commit(), SHA)

    def test_missing_required_signatures_denied(self):
        rules = valid_rules()
        rules[0]["rules"] = [r for r in rules[0]["rules"] if r["type"] != "required_signatures"]
        with self.assertRaises(Denied):
            validate_release_policies(
                {"protected": True, "commit": {"sha": SHA}},
                rules, valid_env(), valid_commit(), SHA)

    def test_bypass_denied(self):
        rules = valid_rules()
        rules[0]["bypass_actors"] = [{"actor_id": 123}]
        with self.assertRaises(Denied):
            validate_release_policies(
                {"protected": True, "commit": {"sha": SHA}},
                rules, valid_env(), valid_commit(), SHA)

    def test_no_independent_reviewer_denied(self):
        env = valid_env()
        env["protection_rules"][0]["prevent_self_review"] = False
        with self.assertRaises(Denied):
            validate_release_policies(
                {"protected": True, "commit": {"sha": SHA}},
                valid_rules(), env, valid_commit(), SHA)

    def test_unsigned_head_denied(self):
        unsigned = {"sha": SHA, "commit": {"verification": {"verified": False, "reason": "unsigned"}}}
        with self.assertRaises(Denied):
            validate_release_policies(
                {"protected": True, "commit": {"sha": SHA}},
                valid_rules(), valid_env(), unsigned, SHA)

    def test_only_exact_main_push_gate_is_eligible(self):
        run = {"id": 50, "head_sha": SHA, "status": "completed",
               "conclusion": "success", "event": "push", "head_branch": "main"}
        self.assertEqual(choose_final_gate_run([run], SHA), 50)
        for change in [{"head_sha": "c" * 40}, {"conclusion": "failure"},
                       {"event": "workflow_dispatch"}, {"status": "in_progress"}]:
            with self.subTest(change=change), self.assertRaises(Denied):
                choose_final_gate_run([dict(run, **change)], SHA)

    def test_manifest_rejects_false_verified_and_unapproved_signer(self):
        manifest = {"schema": "ola-production-evidence-v1", "commit": SHA,
                    "final_status": "ATTESTED_PENDING_HUMAN", "human_gate": "PENDING",
                    "go_no_go": "NO-GO", "production_deployment": "NOT_PERFORMED",
                    "commit_signature_gate": "GITHUB_COMMIT_VERIFIED"}
        signer = {"status": "VERIFIED", "head_sha": SHA, "production_go": "NO-GO",
                  "verified_count": 1, "owner_signed_count": 1,
                  "commits": [{"sha": SHA, "classification": "OWNER_GPG_VERIFIED",
                               "signer": FPR}]}
        self.assertTrue(validate_release_manifest(manifest, signer, SHA, FPR))
        with self.assertRaises(Denied):
            validate_release_manifest(dict(manifest, final_status="VERIFIED"), signer, SHA, FPR)
        with self.assertRaises(Denied):
            validate_release_manifest(manifest, dict(signer, owner_signed_count=0), SHA, FPR)
        with self.assertRaises(Denied):
            validate_release_manifest(manifest, dict(
                signer, commits=[dict(signer["commits"][0], signer="C" * 40)]), SHA, FPR)


if __name__ == "__main__":
    unittest.main()
