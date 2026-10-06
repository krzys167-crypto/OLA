#!/usr/bin/env python3
"""Independent verifier for an OLA decision report artifact."""
import argparse
import hashlib
import json
import sys

def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _reject_constant(name):
    raise ValueError(f"non-finite number {name}")


def _no_duplicate_keys(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate key {key!r}")
        out[key] = value
    return out


def verify(path: str) -> bool:
    """True only for a well-formed report whose stored hash matches its body. Anything else (unreadable file, invalid
    JSON, NaN, duplicate keys, non-object, non-string hash) is False - never a traceback."""
    try:
        with open(path, encoding="utf-8") as handle:
            report = json.load(handle, parse_constant=_reject_constant, object_pairs_hook=_no_duplicate_keys)
        if not isinstance(report, dict):
            return False
        claimed = report.get("report_sha256")
        if not isinstance(claimed, str) or not claimed:
            return False
        body = dict(report)
        body.pop("report_sha256", None)
        actual = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
        return actual == claimed and report.get("schema") == "ola.decision-report.v1"
    except (OSError, ValueError, TypeError, RecursionError, UnicodeError):
        return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("report")
    args = parser.parse_args()
    if not verify(args.report):
        print("DECISION_REPORT=BLOCK")
        return 1
    # the hash is unkeyed: this proves the file was not edited after it was written, not that the decision is right
    print("DECISION_REPORT=VERIFIED")
    print("note: artifact integrity only (unkeyed hash); the correctness of the decision is not checked", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
