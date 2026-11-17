"""Fail-closed release-source contract for all mandatory scan producers."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = "${{ github.event.pull_request.head.sha || github.sha }}"


class ReleaseSourceBindingTest(unittest.TestCase):
    def test_security_checkout_uses_exact_source_sha(self):
        for filename in (
            ".github/workflows/codeql.yml",
            ".github/workflows/supply-chain-evidence.yml",
        ):
            with self.subTest(workflow=filename):
                lines = (ROOT / filename).read_text(encoding="utf-8").splitlines()
                count = 0
                for index, line in enumerate(lines):
                    if "uses: actions/checkout@" not in line:
                        continue
                    count += 1
                    block = "\n".join(lines[index + 1:index + 9])
                    self.assertIn("ref: " + SOURCE, block)
                    self.assertIn("persist-credentials: false", block)
                self.assertGreater(count, 0)

    def test_scan_producers_check_actual_git_head(self):
        for filename in (
            ".github/workflows/codeql.yml",
            ".github/workflows/supply-chain-evidence.yml",
        ):
            with self.subTest(workflow=filename):
                content = (ROOT / filename).read_text(encoding="utf-8")
                self.assertIn('EXPECTED_SOURCE_SHA: ' + SOURCE, content)
                self.assertIn('git rev-parse HEAD', content)
                self.assertIn('if [ "$checked_out" != "$EXPECTED_SOURCE_SHA" ]; then', content)
                self.assertIn('exit 1', content)

    def test_final_gate_requires_v4_and_runtime_contract_gates(self):
        content = (ROOT / ".github/workflows/final-production-gate.yml").read_text(encoding="utf-8")
        start = content.index("required_exact = [")
        end = content.index("required_reference =", start)
        required = content[start:end]
        for gate in (
            "Evidence Cryptography V4 Contract",
            "OLA paid-order PostgreSQL contract",
            "Python package CI",
            "OLA Local Staging Rehearsal",
        ):
            with self.subTest(gate=gate):
                self.assertIn('"' + gate + '"', required)

    def test_release_manifest_never_calls_green_ci_production_verified(self):
        content = (ROOT / ".github/workflows/final-production-gate.yml").read_text(encoding="utf-8")
        self.assertIn('status="ATTESTED_PENDING_HUMAN"', content)
        self.assertNotIn('status="VERIFIED"', content)
        self.assertIn('python -m unittest discover -s tests -p "test_release_source_binding.py"', content)


    def test_runtime_image_source_is_embedded_and_not_environment_asserted(self):
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        nina = (ROOT / ".github/workflows/nina-igor-ollama.yml").read_text(encoding="utf-8")
        release = (ROOT / ".github/workflows/final-production-gate.yml").read_text(encoding="utf-8")
        runtime = (ROOT / "app/runtime_provenance.py").read_text(encoding="utf-8")
        self.assertIn("org.opencontainers.image.revision", dockerfile)
        self.assertIn("chown -R root:root /app", dockerfile)
        self.assertIn("chmod -R a-w /app", dockerfile)
        self.assertIn("ola-build-info.json", dockerfile)
        self.assertIn("--build-arg OLA_SOURCE_COMMIT=", nina)
        self.assertIn("OLA_REQUIRE_BUILD_INFO=1", nina)
        self.assertIn("0000000000000000000000000000000000000000", nina)
        self.assertIn("--build-arg OLA_SOURCE_COMMIT=", release)
        self.assertIn("Assert release image source label", release)
        self.assertIn("OLA_REQUIRE_BUILD_INFO=1", release)
        self.assertIn("/readyz", release)
        self.assertIn("RELEASE_IMAGE_SOURCE_BINDING=VERIFIED", release)
        self.assertIn("build_info_mutable", (ROOT / "app/main.py").read_text(encoding="utf-8"))
        self.assertIn("OLA_RUNTIME_COMMIT is a compatibility fallback", runtime)

    def test_automated_runtime_never_claims_human_approval(self):
        proof = (ROOT / ".github/workflows/nina-real-runtime-provenance.yml").read_text(encoding="utf-8")
        igor = (ROOT / ".github/workflows/igor-independent-evidence.yml").read_text(encoding="utf-8")
        self.assertIn('"human_gate":"PENDING"', proof)
        self.assertNotIn('"human_gate":"VERIFIED"', proof)
        self.assertIn('assert d["human_gate"]=="PENDING"', proof)
        self.assertIn('assert record_hash==hashlib.sha256(', proof)
        self.assertNotIn('assert record_hash==api_key_fingerprint(', proof)
        self.assertIn('assert d["human_gate"]=="PENDING"', igor)


    def test_runtime_workflows_pin_exact_source_and_image_revision(self):
        contracts = {
            ".github/workflows/e2e.yml": "ref: ${{ env.OLA_SOURCE_SHA }}",
            ".github/workflows/ola-product-gate.yml": "ref: ${{ env.OLA_SOURCE_SHA }}",
            ".github/workflows/provenance-gate-final.yml": "ref: ${{ env.OLA_SOURCE_SHA }}",
            ".github/workflows/provenance-mutation.yml": "ref: ${{ env.OLA_SOURCE_SHA }}",
            ".github/workflows/runtime-stress.yml": "ref: ${{ env.OLA_SOURCE_SHA }}",
            ".github/workflows/state-continuity.yml": "ref: ${{ env.OLA_SOURCE_SHA }}",
            ".github/workflows/nina-real-runtime-provenance.yml": "ref: ${{ env.EXPECTED_COMMIT }}",
            ".github/workflows/ollama-real-runtime.yml": "ref: ${{ github.event.pull_request.head.sha || github.sha }}",
            ".github/workflows/igor-independent-evidence.yml": "ref: ${{ env.SOURCE_COMMIT }}",
            ".github/workflows/nina-igor-ollama.yml": "ref: ${{ github.event.pull_request.head.sha || github.sha }}",
        }
        for filename, checkout_ref in contracts.items():
            with self.subTest(workflow=filename):
                content = (ROOT / filename).read_text(encoding="utf-8")
                self.assertIn(checkout_ref, content)
                self.assertIn("--build-arg OLA_SOURCE_COMMIT=", content)
                self.assertIn("org.opencontainers.image.revision", content)
                self.assertIn("OLA_RUNTIME_COMMIT", content)

    def test_independent_igor_uses_the_same_legacy_pepper_source_as_nina(self):
        nina = (ROOT / ".github/workflows/nina-real-runtime-provenance.yml").read_text(encoding="utf-8")
        igor = (ROOT / ".github/workflows/igor-independent-evidence.yml").read_text(encoding="utf-8")
        self.assertIn("OLA_API_KEY_PEPPER: ${{ github.event.pull_request.head.sha || github.sha }}", nina)
        self.assertIn("SOURCE_COMMIT: ${{ inputs.source_commit }}", igor)
        self.assertIn("OLA_API_KEY_PEPPER: ${{ inputs.source_commit }}", igor)
        self.assertNotIn("OLA_API_KEY_PEPPER: ${{ github.sha }}", igor)
        ollama_igor = (ROOT / ".github/workflows/igor-independent-ollama-evidence.yml").read_text(encoding="utf-8")
        self.assertIn("OLA_API_KEY_PEPPER: ${{ inputs.source_commit }}", ollama_igor)
        self.assertIn("ref: ${{ inputs.source_commit }}", ollama_igor)

    def test_nina_ollama_exports_runtime_image_revision_for_igor(self):
        workflow = (ROOT / ".github/workflows/nina-igor-ollama.yml").read_text(encoding="utf-8")
        self.assertIn("EXPECTED_SOURCE_SHA: ${{ github.event.pull_request.head.sha || github.sha }}", workflow)
        self.assertIn("docker image inspect --format", workflow)
        self.assertIn('test "$(cat runtime-image-revision.txt)" = "$EXPECTED_SOURCE_SHA"', workflow)
        self.assertIn('OLA_BUILD_EXPECTED_SHA="$EXPECTED_SOURCE_SHA"', workflow)
        self.assertIn("source_commit: ${{ github.event.pull_request.head.sha || github.sha }}", workflow)
    def test_pull_request_manifest_never_claims_attestation(self):
        content = (ROOT / ".github/workflows/final-production-gate.yml").read_text(encoding="utf-8")
        self.assertIn("github.event_name == 'push' && github.ref == 'refs/heads/main' && success()", content)
        self.assertIn('source_attestation="NOT_PERFORMED"', content)
        self.assertIn('image_attestation="NOT_PERFORMED"', content)
        self.assertIn('status="PREMERGE_CI_PASSED"', content)


if __name__ == "__main__":
    unittest.main()
