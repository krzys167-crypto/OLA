"""CLI:  python -m ola_pipeline run --task "..."   |   python -m ola_pipeline verify <session_dir>"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from . import attest as _attest
from . import verify as _verify
from .config import PipelineConfig
from .errors import ConfigError, SigningError
from .pipeline import Pipeline


def _report(sd: Path) -> int:
    """Prints what the task asks to show before finishing. Reads artifacts only (no pipeline state)."""
    facts = _verify.inspect_session(sd)
    final = {}
    fp = sd / "final.json"
    if fp.is_file():
        final = json.loads(fp.read_text("utf-8"))
    rep = _verify.verify_session(sd)
    print(f"session        : {sd.name}")
    print(f"verifier       : {rep['overall']}  (runtime={rep['runtime_kind']}, failures={len(rep['failures'])})")
    kid = (rep["attestation"] or {}).get("key_id")
    print(f"authenticity   : {rep['authenticity']}" + (f"  key_id={kid}" if kid else "")
          + ("  (key NOT pinned; use `verify --trusted-key`)" if rep["authenticity"] == "UNPINNED_VALID" else ""))
    for e in facts.envelopes:
        refs = e.get("refs") or {}
        print(f"\n[{e['seq']:02d}] {e['agent_id']:<5} run_id={e['run_id']}  iter={e['iteration']}  "
              f"parent={e['parent_run_id']}  status={e['execution_status']}")
        print(f"     provider={e['provider']} model={e['model']} digest={e.get('model_digest')}")
        for k in ("input_hash", "prompt_hash", "output_hash", "runtime_proof_hash"):
            print(f"     {k:<19}: {e.get(k)}")
        if refs.get("evaluation_hash"):
            print(f"     {'evaluation_hash':<19}: {refs['evaluation_hash']}")
        print(f"     envelope_hash      : {e['envelope_hash']}")
    print("\nFINAL")
    for k in ("run_id", "source_sha", "provider", "model", "iterations", "nina_status", "igor_status",
              "gate_state", "evidence_class", "chain_head"):
        print(f"  {k:<15}: {final.get(k)}")
    for r in final.get("gate_reasons", []):
        print(f"  reason         : {r}")
    for w in rep["warnings"]:
        print(f"  warning        : {w}")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="ola_pipeline")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    g = r.add_mutually_exclusive_group(required=True)
    g.add_argument("--task")
    g.add_argument("--task-file")
    v = sub.add_parser("verify")
    v.add_argument("session_dir")
    v.add_argument("--expected-source-sha")
    v.add_argument("--scan-root")
    v.add_argument("--trusted-key")
    v.add_argument("--json", action="store_true")
    k = sub.add_parser("keygen", help="create an Ed25519 signing key (0600) + public key file; never overwrites")
    k.add_argument("--out", required=True)
    rp = sub.add_parser("report", help="human-readable run/artifact/hash table for a session")
    rp.add_argument("session_dir")
    a = ap.parse_args(argv)

    if a.cmd == "report":
        return _report(Path(a.session_dir))

    if a.cmd == "keygen":
        try:
            info = _attest.generate_keypair(Path(a.out))
        except SigningError as e:
            print(json.dumps({"error": str(e)}), file=sys.stderr)
            return 1
        print(json.dumps(info, indent=2))
        print("Keep the private key file secret and OUTSIDE the evidence vault. Pin the PUBLIC key "
              "(public_key / .pub file) out of band: verify with --trusted-key.", file=sys.stderr)
        return 0

    if a.cmd == "verify":
        args = [a.session_dir]
        if a.expected_source_sha:
            args += ["--expected-source-sha", a.expected_source_sha]
        if a.scan_root:
            args += ["--scan-root", a.scan_root]
        if a.trusted_key:
            args += ["--trusted-key", a.trusted_key]
        if a.json:
            args.append("--json")
        return _verify.main(args)

    task = a.task if a.task is not None else Path(a.task_file).read_text("utf-8")
    try:
        cfg = PipelineConfig.from_env()
    except ConfigError as e:
        print(json.dumps({"gate_state": "BLOCKED", "error": f"configuration: {e}"}))
        return 1
    try:
        run = Pipeline(cfg).run(task)
    except SigningError as e:
        unsigned = e.run
        print(json.dumps({"gate_state": unsigned.final["gate_state"] if unsigned else "BLOCKED",
                          "error": f"signing requested but failed: {e}"}), file=sys.stderr)
        if unsigned:
            print(f"session_dir (UNSIGNED): {unsigned.session_dir}", file=sys.stderr)
        return 1
    print(json.dumps(run.final, indent=2, sort_keys=True, ensure_ascii=False))
    print(f"session_dir: {run.session_dir}", file=sys.stderr)
    if run.attestation:
        print(f"attestation: SIGNED key_id={run.attestation['key_id']} (authenticity is established only "
              "when you verify with --trusted-key <pinned public key>)", file=sys.stderr)
    else:
        print("attestation: NONE (OLA_SIGNING_KEY_FILE not set)", file=sys.stderr)
    return 0 if run.final["gate_state"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
