#!/usr/bin/env python3
"""Local report check only; never an independent execution verifier."""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.decision_report_v2 import inspect_decision_report_v2


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report")
    args = parser.parse_args()
    try:
        with open(args.report, encoding="utf-8") as handle:
            report = json.load(handle, object_pairs_hook=_unique)
        result = inspect_decision_report_v2(report)
    except (OSError, ValueError, RecursionError):
        result = {"integrity": "BLOCKED", "assurance": "BLOCKED", "production_eligible": False}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["integrity"] == "LOCAL" else 1


if __name__ == "__main__":
    sys.exit(main())
