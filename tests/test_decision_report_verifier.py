import json
import subprocess
import sys


def test_independent_decision_report_verifier_blocks_tamper(tmp_path):
    report = {
        "schema": "ola.decision-report.v1",
        "task_id": "t1",
        "run_id": "r1",
        "policy": {"status": "REVIEW"},
    }
    from app.hashchain import canonical_json
    import hashlib

    report["report_sha256"] = hashlib.sha256(
        canonical_json({k: v for k, v in report.items() if k != "report_sha256"}).encode()
    ).hexdigest()

    path = tmp_path / "report.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    good = subprocess.run([sys.executable, "scripts/verify_decision_report.py", str(path)], capture_output=True, text=True)
    assert good.returncode == 0
    assert "DECISION_REPORT=LOCAL" in good.stdout
    assert "VERIFIED" not in good.stdout
    assert "EXECUTION_ASSURANCE=UNKNOWN" in good.stdout

    report["policy"]["status"] = "VERIFIED"
    path.write_text(json.dumps(report), encoding="utf-8")
    bad = subprocess.run([sys.executable, "scripts/verify_decision_report.py", str(path)], capture_output=True, text=True)
    assert bad.returncode != 0
    assert "DECISION_REPORT=BLOCK" in bad.stdout
