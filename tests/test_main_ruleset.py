"""Regression contract for the GitHub main protection handoff."""
import importlib.util
from pathlib import Path

PATH = Path(__file__).resolve().parents[1] / "scripts" / "apply_main_ruleset.py"
spec = importlib.util.spec_from_file_location("main_ruleset", PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_policy_is_active_nobypass_main_only():
    p = module.policy()
    assert p["target"] == "branch"
    assert p["enforcement"] == "active"
    assert p["bypass_actors"] == []
    assert p["conditions"]["ref_name"] == {"include": ["refs/heads/main"], "exclude": []}
    assert {"required_signatures", "pull_request", "required_status_checks",
            "non_fast_forward", "deletion"} <= {r["type"] for r in p["rules"]}


def test_policy_has_independent_review_and_exact_security_checks():
    rules = {r["type"]: r for r in module.policy()["rules"]}
    review = rules["pull_request"]["parameters"]
    assert review["required_approving_review_count"] >= 1
    assert review["dismiss_stale_reviews_on_push"]
    assert review["require_last_push_approval"]
    assert review["required_review_thread_resolution"]
    checks = rules["required_status_checks"]["parameters"]
    assert checks["strict_required_status_checks_policy"]
    names = {c["context"] for c in checks["required_status_checks"]}
    assert {"CodeQL", "gitleaks", "dag-tests", "final-production"} <= names


def test_never_mutates_without_explicit_apply(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["apply_main_ruleset.py"])
    monkeypatch.setattr(module, "apply", lambda: (_ for _ in ()).throw(AssertionError("MUTATION")))
    assert module.main() == 0
    assert '"status": "DRY_RUN_ONLY"' in capsys.readouterr().out
