#!/usr/bin/env python3
"""Local checksum inspection of a legacy OLA report; not execution attestation."""
import argparse
import hashlib
import json
import sys

def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def verify(path: str) -> bool:
    with open(path, encoding="utf-8") as handle:
        report = json.load(handle, object_pairs_hook=unique_pairs)
    claimed = report.get("report_sha256")
    if not claimed:
        return False
    body = dict(report)
    body.pop("report_sha256", None)
    actual = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
    return actual == claimed and report.get("schema") == "ola.decision-report.v1"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("report")
    args = parser.parse_args()
    try:
        valid = verify(args.report)
    except (OSError, ValueError, TypeError, AttributeError):
        valid = False
    if not valid:
        print("DECISION_REPORT=BLOCK")
        return 1
    print("DECISION_REPORT=LOCAL")
    print("EXECUTION_ASSURANCE=UNKNOWN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
