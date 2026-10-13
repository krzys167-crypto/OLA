"""Guard against accidental automatic publication of Docker Hub images."""
import unittest
from pathlib import Path

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/ola-docker-cloud.yml"


class DockerCloudWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.yml = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("  build-only:", self.yml)
        self.assertIn("  publish-reviewed-image:", self.yml)
        self.build, self.publish = self.yml.split("  publish-reviewed-image:", 1)

    def test_pull_request_and_main_push_are_build_only(self):
        self.assertIn("if: github.event_name != 'workflow_dispatch'", self.build)
        self.assertIn("push: false", self.build)
        self.assertIn("outputs: type=cacheonly", self.build)
        self.assertNotIn("docker/login-action@", self.build)
        self.assertNotIn("driver: cloud", self.build)

    def test_publication_requires_manual_source_bound_approval(self):
        self.assertIn("github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main'", self.publish)
        self.assertIn("environment: production", self.publish)
        self.assertIn("docker_cloud_release_gate.py preflight", self.publish)
        self.assertIn("docker_cloud_release_gate.py artifact", self.publish)
        self.assertIn("assert_manifest_policy.py", self.publish)

    def test_release_is_sha_tagged_without_latest(self):
        self.assertNotIn(":latest", self.publish)
        self.assertIn("krzysztof1678/ola:sha-", self.publish)
        self.assertIn("push: true", self.publish)
        self.assertIn("provenance: mode=max", self.publish)
        self.assertIn("sbom: true", self.publish)
        self.assertIn("docker buildx imagetools inspect", self.publish)

    def test_secrets_are_not_used_before_verification(self):
        sign = self.publish.index("docker_cloud_release_gate.py artifact")
        auth = self.publish.index("docker/login-action@")
        self.assertLess(sign, auth)
        self.assertNotIn("secrets.DOCKER_PAT", self.publish[:auth])


if __name__ == "__main__":
    unittest.main()
