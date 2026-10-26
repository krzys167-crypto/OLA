#!/usr/bin/env python3
"""Fail closed on CodeQL HIGH/CRITICAL SARIF findings and missing reports.

CodeQL normally stores security-severity in tool.driver.rules[].properties,
not necessarily in results[].properties. Both locations must be checked.
"""
import glob
import json
from pathlib import Path
import sys


def severity_of(properties):
    try:
        return float((properties or {}).get("security-severity"))
    except (TypeError, ValueError):
        return 0.0


def check(directory):
    files = sorted(glob.glob(str(Path(directory) / "*.sarif")))
    if not files:
        print(json.dumps({"status": "BLOCK", "error": "CODEQL_SARIF_MISSING", "files": []}))
        return 1

    findings = []
    try:
        for file in files:
            with open(file, encoding="utf-8") as stream:
                document = json.load(stream)
            for run in document.get("runs", []):
                driver = run.get("tool", {}).get("driver", {})
                rules = driver.get("rules", [])
                by_id = {rule.get("id"): rule for rule in rules if rule.get("id")}
                for result in run.get("results", []):
                    rule_id = result.get("ruleId")
                    rule = by_id.get(rule_id, {})
                    index = result.get("ruleIndex")
                    if not rule and isinstance(index, int) and 0 <= index < len(rules):
                        rule = rules[index]
                        rule_id = rule_id or rule.get("id")
                    severity = max(
                        severity_of(rule.get("properties")),
                        severity_of(result.get("properties")),
                    )
                    if severity >= 7.0:
                        findings.append({
                            "rule": rule_id or "UNKNOWN_RULE",
                            "severity": severity,
                            "tool": driver.get("name", "CodeQL"),
                        })
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(json.dumps({
            "status": "BLOCK",
            "error": "INVALID_CODEQL_SARIF",
            "details": type(exc).__name__,
        }, sort_keys=True))
        return 1

    blocked = bool(findings)
    print(json.dumps({
        "status": "BLOCK" if blocked else "PASS",
        "codeql_sarif_files": files,
        "high_or_critical_findings": findings,
    }, sort_keys=True))
    return 1 if blocked else 0


if __name__ == "__main__":
    sys.exit(check(sys.argv[1] if len(sys.argv) > 1 else "codeql-results"))
