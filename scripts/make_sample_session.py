#!/usr/bin/env python3
"""Generate the SYNTHETIC sample session shown in docs/sales/sample/.

  python scripts/make_sample_session.py <empty_output_dir>

The "model" is the repository's Ollama TEST DOUBLE (tests/pipeline_suite/fake_ollama.py). Its answers are TEXT WRITTEN BY
THE AUTHOR in this file, and the "judge" verdict is scripted too. So the session proves the record structure and the
verifier, and nothing about model quality or about any real analysis. The verifier says so itself: overall PARTIAL,
because the runtime is a declared test double. Every run produces new run ids and timestamps, so the output is not
byte-for-byte reproducible; the committed copy is one such run."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests" / "pipeline_suite"))

from fake_ollama import FakeOllama  # noqa: E402
from ola_pipeline import Pipeline, Policy, verify_session  # noqa: E402
from ola_pipeline.config import PipelineConfig, ProviderConfig  # noqa: E402

TASK = (
    "SYNTHETIC SAMPLE - not a real customer, not a real analysis, no real model. "
    "Process: incoming rental-application e-mails at a FICTIONAL property agency. "
    "Sample set: 3 invented e-mails. "
    "Write a short map of which steps could be automated and which must stay with a person."
)

# Written by the author. No model produced this text.
SCRIPTED_MAP = """QUICK MAP - SYNTHETIC SAMPLE (text scripted by the author; no model wrote it)

Process: rental-application e-mails at a fictional agency. Sample: 3 invented e-mails.

Could be automated (on the sample): sorting by property reference; extracting name, requested date, attached document types; \
flagging e-mails with a missing attachment.
Must stay with a person: judging an applicant; any reply that promises a viewing or a price; anything that touches an \
applicant's personal documents beyond checking that they are present.
Not decided on this sample: how often attachments are missing in real life (3 e-mails say nothing about that).

Next step in a real engagement: a larger sample set from the customer, and a fixed-price quote for the automatable part."""

JUDGE = json.dumps({
    "decision": "PASS", "quality_score": 90, "findings": [], "required_corrections": [],
    "reason": "SCRIPTED verdict of the test double; it says nothing about the quality of the map.",
})


def main(out: Path) -> int:
    if out.exists() and any(out.iterdir()):
        print("output directory must be empty", file=sys.stderr)
        return 2
    out.mkdir(parents=True, exist_ok=True)
    fake = FakeOllama().start()
    try:
        fake.add_model("sample-nina", digest="a1b2c3d4" * 8)
        fake.add_model("sample-igor")
        fake.script("sample-nina", SCRIPTED_MAP)
        fake.script("sample-igor", JUDGE)
        cfg = PipelineConfig(
            nina=ProviderConfig("ollama-local", "sample-nina", base_url=fake.url, timeout_s=10.0),
            igor=ProviderConfig("ollama-local", "sample-igor", base_url=fake.url, timeout_s=10.0, temperature=0.0),
            policy=Policy(allow_test_double=True),
            vault_root=out / "vault",
        )
        run = Pipeline(cfg).run(TASK)
    finally:
        fake.stop()
    report = verify_session(run.session_dir)
    print(json.dumps({"session_dir": str(run.session_dir), "overall": report["overall"],
                      "failures": report["failures"]}, indent=2))
    return 0 if report["overall"] == "PARTIAL" and not report["failures"] else 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    sys.exit(main(Path(sys.argv[1])))
