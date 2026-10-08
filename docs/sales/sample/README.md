# SYNTHETIC SAMPLE - what an OLA evidence record looks like, and how a customer checks one

**SYNTHETIC / TEST EVIDENCE ONLY.** This is not a customer, not a real analysis and not the output of any model.
Show it to explain the record and the check. Never show it as a result, as a reference or as proof of quality.

## What it is
`ses_ec3800514ecb02f044f18808/` is a session folder written by the OLA pipeline against the repository's Ollama **test
double** (`tests/pipeline_suite/fake_ollama.py`). Three things in it are made up, on purpose:
- the task text ("rental-application e-mails at a fictional property agency, 3 invented e-mails");
- the "map" the producer returns: text **written by the author** in `scripts/make_sample_session.py`; no model wrote it;
- the judge's verdict (PASS, score 90): **scripted**; it says nothing about the quality of the map.

So the sample demonstrates only the record structure and the verifier. Because the runtime is a declared test double, the
verifier's best possible overall verdict for it is **PARTIAL**, and it must stay that way. A record may be called VERIFIED only
when a live runtime was observed and the gate passed; this one never will be.

## What is in the folder
| Path | What it holds |
|---|---|
| `envelopes/0001_*.json` | the producer run: model name and digest, hashes of the input, the prompt and the output |
| `envelopes/0002_*.json` | the judge run, linked to the producer by `parent_run_id` |
| `envelopes/0003_*.json` | a calibration check of the judge on a question with a known wrong answer (the "canary") |
| `artifacts/<sha256>` | the texts themselves (task, prompts, produced text, judge reply), each stored under its own hash |
| `final.json` | the gate result, the chain head, and the source commit the code ran from |

## How to check it (standard library only, nothing to install)
From a checkout of this repository:

    python ola_pipeline/verify.py docs/sales/sample/ses_ec3800514ecb02f044f18808

Output on 2026-10-08 (exit code 3):

    overall=PARTIAL outcome=PASS runtime=TEST_DOUBLE
    authenticity=NONE

Exit codes: 0 VERIFIED, 1 FAILED, 2 CONSISTENT, 3 PARTIAL. `ola_pipeline/verify.py` is one file and can be copied alone.
After a `git checkout` the files are writable, so the verifier may add `warn: ... file is not read-only` lines; they are
warnings, not failures.

## See it fail (the useful part of a demo)
Copy the folder, change one word in `artifacts/9435a2649d66...` (the produced text), and run the same command on the copy.
On 2026-10-08, changing "a person" to "a robot" gave (exit code 1):

    overall=FAILED outcome=PASS runtime=TEST_DOUBLE
      FAIL: 0001_run_3c3ae9cc....json:output: artifact 9435a2649d66… content does not match its hash (hash mismatch)
      FAIL: final.json gate_state does not match the artifacts (claimed != derived)
      FAIL: final.json gate_reasons does not match the artifacts (claimed != derived)

## What a clean check shows, and what it does not
Shows: every file matches its recorded hash; the three runs point at each other; the gate result recorded in `final.json` can
be re-derived from the artifacts; the pipeline code ran from the recorded source commit `559cb1d` and the working tree was
reported clean (`source_sha_kind` is `git-clean`). The generator script that drove this run is newer than that commit and is
not part of it.

Does **not** show:
- that a real model ran (here none did), or that the analysis is right;
- who wrote the record: `authenticity=NONE`, there is no signature. With a signing key and the customer pinning the public
  key out of band (`--trusted-key`) the verifier can report `PINNED_VALID`; without the pin a valid signature is only
  `UNPINNED_VALID` and proves nothing about the signer;
- that the operator did not write the whole record afterwards. That needs the head hash published or timestamped outside OLA;
  the timestamp module exists but is not wired into this record.

## Differences in a real engagement
- A live runtime (Ollama, observed) replaces the test double. Whether the verdict then reaches VERIFIED depends on the
  judge: in the project's own CI one of two live runs did (`docs/pipeline-bridge.md`). Do not promise it.
- The artifacts contain the task text, the prompts and the produced text. For a real customer that means **parts of the
  customer's sample documents sit in the record**. Agree with the customer, before the work, what is shared and where it is
  stored.
- The Stripe receipt (`ola.receipt/1`, `tools/verify_receipt.py`) exists only for a payment made through the Stripe flow. For a
  hand-invoiced tier the evidence of the analysis is the session folder, checked as above.

## Regenerate
    python scripts/make_sample_session.py <empty_output_dir>

Run ids and timestamps change on every run; the committed folder is one run, kept so that the walk-through above is
repeatable. `tests/test_sales_sample.py` checks that it still verifies as PARTIAL, that tampering is caught and that the
labels are present.
