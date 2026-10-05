"""Check governance/controls.json against the repository. A control is only as real as what backs it.

Static checks (always):
  * every mechanism file exists and contains its symbol
  * every test id (file::function) exists (parsed with ast, not grep)
  * every CI entry names an existing workflow and job
  * CI COVERAGE: the control's test files are run by at least one listed CI job - a job whose pytest line names no
    tests/ path runs everything; a job that names paths runs only those. A test CI never runs is reported.
With --run the referenced tests are executed and each control gets a computed status:
  VERIFIED_LOCALLY   every referenced test passed
  FAILING            at least one failed or errored
  NOT_RUN            statically fine, not executed (the default)
  BROKEN_REFERENCE   something above does not exist
Status is never read from the JSON. Exit code 1 if any reference is broken, 2 if --run and a test failed.
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

ROOT = Path(__file__).resolve().parents[1]
CONTROLS = ROOT / "governance" / "controls.json"


def test_functions(path: Path) -> Set[str]:
    try:
        tree = ast.parse(path.read_text("utf-8"))
    except (OSError, SyntaxError):
        return set()
    # module-level functions only: a nested "test_x" or a method of a helper class is not collected by pytest
    return {n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            and n.name.startswith("test")}


def workflow_jobs(path: Path) -> Dict[str, str]:
    """job id -> text of its block (lines indented deeper than the job key). Enough for 'does it exist / run pytest'."""
    try:
        lines = path.read_text("utf-8").splitlines()
    except OSError:
        return {}
    jobs: Dict[str, List[str]] = {}
    in_jobs, cur = False, None
    for ln in lines:
        if re.match(r"^jobs:\s*$", ln):
            in_jobs, cur = True, None
            continue
        if in_jobs and re.match(r"^\S", ln):
            in_jobs, cur = False, None
        m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", ln) if in_jobs else None
        if m:
            cur = m.group(1)
            jobs[cur] = []
        elif cur is not None:
            jobs[cur].append(ln)
    return {k: "\n".join(v) for k, v in jobs.items()}


def pytest_scope(block: str) -> Optional[Set[str]]:
    """None = the job runs no pytest; {'*'} = all tests; else the set of test files named on the pytest lines."""
    files: Set[str] = set()
    seen = False
    for ln in block.splitlines():
        if re.search(r"\bpytest\b", ln) and not ln.strip().startswith("#") and "pip install" not in ln:
            seen = True
            named = set(re.findall(r"tests/[A-Za-z0-9_./-]+\.py", ln))
            if not named:
                return {"*"}
            files |= named
    return files if seen else None


def check(controls: List[Dict[str, Any]], root: Path = ROOT) -> Tuple[List[str], Dict[str, Dict[str, Any]]]:
    errors: List[str] = []
    info: Dict[str, Dict[str, Any]] = {}
    ids = [c.get("id") for c in controls]
    if len(set(ids)) != len(ids):
        errors.append("duplicate control ids")
    for c in controls:
        cid = c.get("id", "?")
        broken: List[str] = []
        if not c.get("statement") or not c.get("limits"):
            broken.append("statement and limits are required (a control without a stated limit is a claim)")
        if not c.get("tests"):
            broken.append("no tests: a control with nothing that checks it")
        for m in c.get("mechanism", []):
            p = root / m["file"]
            if not p.is_file():
                broken.append(f"mechanism file missing: {m['file']}")
            elif m.get("symbol") and m["symbol"] not in p.read_text("utf-8", errors="replace"):
                broken.append(f"symbol {m['symbol']!r} not found in {m['file']}")
        test_files: Set[str] = set()
        for t in c.get("tests", []):
            f, _, name = t.partition("::")
            test_files.add(f)
            if not (root / f).is_file():
                broken.append(f"test file missing: {f}")
            elif name not in test_functions(root / f):
                broken.append(f"test not found: {t}")
        covered: Set[str] = set()
        for ci in c.get("ci", []):
            wf = root / ".github" / "workflows" / ci["workflow"]
            jobs = workflow_jobs(wf)
            if ci["job"] not in jobs:
                broken.append(f"CI job missing: {ci['workflow']}::{ci['job']}")
                continue
            scope = pytest_scope(jobs[ci["job"]])
            if scope is None:
                broken.append(f"CI job runs no pytest: {ci['workflow']}::{ci['job']}")
            elif "*" in scope:
                covered |= test_files
            else:
                covered |= test_files & scope
        for f in sorted(test_files - covered):
            broken.append(f"no listed CI job runs {f}")
        info[cid] = {"broken": broken, "tests": list(c.get("tests", [])), "status": "BROKEN_REFERENCE" if broken else "NOT_RUN"}
        errors += [f"{cid}: {b}" for b in broken]
    return errors, info


def run_tests(controls: List[Dict[str, Any]], info: Dict[str, Dict[str, Any]], root: Path = ROOT) -> None:
    node_ids = sorted({t for c in controls if not info[c["id"]]["broken"] for t in c.get("tests", [])})   # a bad id would abort the whole run
    with tempfile.TemporaryDirectory() as td:
        xml = Path(td) / "r.xml"
        subprocess.run([sys.executable, "-m", "pytest", "-o", "addopts=", "-p", "no:cacheprovider", "-W", "ignore", "-q",
                        f"--junitxml={xml}", *node_ids], cwd=root, capture_output=True, text=True)
        seen: Dict[str, List[str]] = {}
        if xml.is_file():
            for tc in ET.parse(xml).getroot().iter("testcase"):
                # a parametrized test is one test id with many instances: ALL of them must pass
                key = tc.get("classname", "").replace(".", "/") + "::" + re.sub(r"\[.*\]$", "", tc.get("name", ""))
                bad = tc.find("failure") is not None or tc.find("error") is not None
                skipped = tc.find("skipped") is not None
                seen.setdefault(key, []).append("failed" if bad else ("skipped" if skipped else "passed"))
        outcome = {k: ("failed" if "failed" in v else "skipped" if "skipped" in v else "passed") for k, v in seen.items()}
    for c in controls:
        if info[c["id"]]["broken"]:
            continue
        res = []
        for t in c["tests"]:
            f, _, name = t.partition("::")
            key = f[:-3] + "::" + name
            res.append(outcome.get(key, "missing"))
        info[c["id"]]["results"] = dict(zip(c["tests"], res))
        info[c["id"]]["status"] = "VERIFIED_LOCALLY" if all(r == "passed" for r in res) else "FAILING"


def to_markdown(controls: List[Dict[str, Any]], info: Dict[str, Dict[str, Any]], with_status: bool) -> str:
    head = ["# Control evidence matrix", "",
            "Generated by `python scripts/check_controls.py --write-md` from `governance/controls.json`. A control lists the "
            "mechanism, the tests that check it, the CI job that runs them, and its stated limit. **Status is not stored**: "
            "`python scripts/check_controls.py --run` computes it (`VERIFIED_LOCALLY` = every referenced test passed here).", "",
            "| ID | Control | Tests | CI | Limit (what this does not prove) |", "|---|---|---|---|---|"]
    rows = []
    for c in controls:
        ci = ", ".join(f"`{x['workflow']}`::{x['job']}" for x in c.get("ci", []))
        rows.append(f"| {c['id']} | {c['statement']} | {len(c['tests'])} | {ci} | {c['limits']} |")
    return "\n".join(head + rows) + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--run", action="store_true", help="execute the referenced tests and compute the status")
    p.add_argument("--write-md", action="store_true", help="write docs/control-evidence-matrix.md")
    a = p.parse_args(argv)
    doc = json.loads(CONTROLS.read_text("utf-8"))
    controls = doc["controls"]
    errors, info = check(controls)
    if a.run and not errors:
        run_tests(controls, info)
    for c in controls:
        i = info[c["id"]]
        print(f"{c['id']:<6} {i['status']:<17} {len(c['tests'])} tests")
    for e in errors:
        print("ERROR", e, file=sys.stderr)
    if a.write_md:
        (ROOT / "docs" / "control-evidence-matrix.md").write_text(to_markdown(controls, info, False), "utf-8")
    if errors:
        return 1
    return 2 if any(i["status"] == "FAILING" for i in info.values()) else 0


if __name__ == "__main__":
    sys.exit(main())
