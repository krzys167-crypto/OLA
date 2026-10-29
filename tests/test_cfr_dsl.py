"""CFR scenario DSL v0 (cfr_scenarios/dsl): the schema, the semantic rules, the generated manifest, and drift.

A scenario file is only worth having if it cannot disagree with the code that runs it. These tests compare the DSL
document of Certificate Apocalypse with the range (cfr_range.py), the container definition (docker/compose.yaml), the
load script (k6_load.js), the fault injector, the assertion script and the manifest the server pins; and they feed the
validator documents that are wrong in one way each, which it must reject for that reason.

Needs PyYAML and jsonschema, neither of which is a runtime dependency of the service: without them the module is skipped
(pip install PyYAML jsonschema).
"""
import copy
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml", reason="PyYAML missing: pip install PyYAML")
jsonschema = pytest.importorskip("jsonschema", reason="jsonschema missing: pip install jsonschema")

from app import cfr  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
DIR = ROOT / "cfr_scenarios" / "certificate-apocalypse"
sys.path.insert(0, str(ROOT / "cfr_scenarios" / "dsl"))
sys.path.insert(0, str(DIR))
import cfr_dsl as dsl  # noqa: E402
import cfr_range as rng  # noqa: E402
import score as ca_score  # noqa: E402

SCENARIO = DIR / "scenario.yaml"
MANIFEST = json.loads((DIR / "manifest.json").read_text())
DOC = yaml.safe_load(SCENARIO.read_text())


def mutated(fn):
    doc = copy.deepcopy(DOC)
    fn(doc)
    return doc


def errors_of(fn, root=DIR):
    return dsl.validate(mutated(fn), root)


# ------------------------------------------------------------------ the shipped scenario
def test_the_schema_is_itself_a_valid_draft_2020_12_schema():
    jsonschema.Draft202012Validator.check_schema(dsl.load_schema())


def test_certificate_apocalypse_is_valid_and_its_files_exist():
    assert dsl.validate(DOC, DIR) == []


def test_the_generated_manifest_is_the_manifest_the_server_pins():
    generated = dsl.to_manifest(DOC)
    assert generated == MANIFEST
    assert cfr.validate_manifest(generated) == cfr.validate_manifest(MANIFEST)


def test_the_generated_manifest_passes_the_servers_own_validation():
    cfr.validate_manifest(dsl.to_manifest(DOC))


# ------------------------------------------------------------------ no drift between the DSL and the code
def test_services_match_the_range():
    assert [s["name"] for s in DOC["services"]] == list(rng.SERVICES)
    assert {s["name"]: s["tls"]["cert_file"] for s in DOC["services"]} == rng.PEM
    targeted = {t for f in DOC["faults"] for t in f["targets"]}
    assert targeted == set(rng.AFFECTED)
    assert {s["name"] for s in DOC["services"]} - targeted == set(rng.UNAFFECTED)


def test_fault_ids_are_the_range_variants_in_the_same_order():
    # the server picks the variant by index: a different order is a different scenario
    assert [f["id"] for f in DOC["faults"]] == list(rng.VARIANTS)


def test_the_host_template_is_what_the_range_derives_from_the_seed():
    mut = DOC["env"]["user_mutation"]["host"]
    for seed in ("0123456789abcdef", "fedcba9876543210", "a" * 64):
        assert mut["template"].format(seed_prefix=seed[:mut["seed_prefix_chars"]]) == rng.host_for(seed)


def test_probe_interval_and_stable_window_match_the_range():
    assert DOC["traffic"]["probe"]["interval_s"] == rng.INTERVAL_S
    stable = next(a for a in DOC["assertions"] if a["id"] == "health_stable_10s")
    assert stable["check"]["window_s"] == rng.STABLE_S


def test_assertion_ids_are_exactly_those_assertions_sh_emits():
    out = subprocess.run([str(DIR / "assertions.sh")], capture_output=True, text=True,
                         env={"PATH": "/usr/bin:/bin", "STATE": "/nonexistent"}).stdout
    emitted = {json.loads(line)["id"] for line in out.splitlines()}
    assert emitted == {a["id"] for a in DOC["assertions"]}


def test_k6_script_carries_the_declared_load_and_thresholds():
    load, js = DOC["traffic"]["load"], (DIR / DOC["traffic"]["load"]["script"]).read_text()
    for needle in (f"vus: {load['vus']},", f"duration: '{load['duration_s']}s'",
                   f"http_req_failed: ['rate<{load['thresholds']['error_rate_lt']}']",
                   f"http_req_duration: ['p(95)<{load['thresholds']['p95_ms_lt']}']", f"sleep({load['think_time_s']})"):
        assert needle in js, needle
    assert DOC["traffic"]["probe"]["path"] == "/health" and "/health" in js


def test_the_fault_injector_implements_every_fault_with_its_declared_parameters():
    sh = (DIR / "scripts" / "gen_bad_cert.sh").read_text()
    by_id = {f["id"]: f for f in DOC["faults"]}
    for fid in by_id:
        assert re.search(rf"^\s*{re.escape(fid)}\)", sh, re.M), f"no case for {fid}"
    p = by_id["expired"]["params"]
    assert f"-startdate {p['not_before'].replace('-', '')}000000Z" in sh
    assert f"-enddate {p['not_after'].replace('-', '')}000000Z" in sh
    assert f'san "{by_id["wrong-san"]["params"]["san_prefix"]}$HOST"' in sh
    assert "openssl req -x509" in sh.split("untrusted-chain)")[1].split("wrong-san)")[0]


def test_evidence_collectors_are_what_score_py_digests(tmp_path):
    (tmp_path / "certs").mkdir()
    for c in DOC["evidence"]["collect"]:
        (tmp_path / c["file"]).write_text("x")
    assert set(ca_score.artifact_digests(tmp_path)) == {c["id"] for c in DOC["evidence"]["collect"]}


def test_container_limits_and_published_ports_match_compose():
    compose = yaml.safe_load((DIR / "docker" / "compose.yaml").read_text())
    role, lim = compose["x-role"], DOC["env"]["limits"]
    assert role["mem_limit"] == f"{lim['mem_mb']}m" and role["pids_limit"] == lim["pids"]
    assert role["read_only"] is lim["read_only"]
    assert (role["cap_drop"] == ["ALL"]) is lim["cap_drop_all"]
    assert ("no-new-privileges:true" in role["security_opt"]) is lim["no_new_privileges"]
    assert any(t.startswith(f"/tmp:size={lim['tmpfs_mb']}m") for t in role["tmpfs"])
    for s in DOC["services"]:
        p = s["ports"]
        assert compose["services"][s["name"]]["ports"] == [f"{lim['publish_on']}:${{{p['host_env']}:-{p['host_default']}}}:{p['container']}"]


def test_k3d_is_declared_not_provided_and_nothing_k8s_is_shipped():
    assert DOC["env"]["modes"]["k3d"] == {"status": "not_provided", "files": []}
    shipped = {p.name.lower() for p in DIR.rglob("*")}
    assert not {n for n in shipped if "k3d" in n or n in ("k8s", "kubernetes", "manifests", "kustomization.yaml")}


def test_the_independent_measurement_block_is_the_witness_the_directory_ships():
    im = DOC["evidence"]["independent_measurement"]
    assert (DIR / im["witness"]["script"]).is_file()
    assert im["required"] is False                     # as shipped: see README, "Independent witness"


# ------------------------------------------------------------------ the validator rejects what is wrong
def _set(path, value):
    def fn(doc):
        node = doc
        for k in path[:-1]:
            node = node[k]
        node[path[-1]] = value
    return fn


def _drop(key):
    return lambda doc: doc.pop(key)


SCHEMA_CASES = [
    ("an unknown top-level key", lambda d: d.update(foo=1), "foo"),
    ("a missing section", _drop("hints"), "hints"),
    ("a wrong dsl_version", _set(["dsl_version"], "1"), "dsl_version"),
    ("a fault kind no runner implements", _set(["faults", 0, "kind"], "dns_poison"), "dns_poison"),
    ("a parameter that belongs to another fault kind", _set(["faults", 0, "params"], {"san_prefix": "x-"}), "faults/0/params"),
    ("a service of the wrong role", _set(["services", 0, "role"], "kafka_broker"), "services/0/role"),
    ("a traffic tool no runner implements", _set(["traffic", "load", "tool"], "vegeta"), "traffic/load/tool"),
    ("k6 declared as scored", _set(["traffic", "load", "scored"], True), "traffic/load/scored"),
    ("a signature algorithm other than ed25519", _set(["evidence", "signing", "algorithm"], "rsa"), "evidence/signing/algorithm"),
    ("a host template with no seed in it", _set(["env", "user_mutation", "host", "template"], "svc.range.test"),
     "user_mutation/host/template"),
    ("a path that climbs out of the directory", _set(["traffic", "load", "script"], "../x.js"), "traffic/load/script"),
    ("a negative weight", _set(["scoring", "weights", "latency"], -0.1), "scoring/weights/latency"),
    ("an unknown assertion kind", _set(["assertions", 0, "kind"], "optional"), "assertions/0/kind"),
    ("a port variable that is not an upper-case name", _set(["services", 0, "ports", "host_env"], "cfr_port_api"),
     "services/0/ports/host_env"),
]


@pytest.mark.parametrize("name,fn,expect", SCHEMA_CASES, ids=[c[0] for c in SCHEMA_CASES])
def test_the_schema_rejects(name, fn, expect):
    errs = dsl.schema_errors(mutated(fn))
    assert errs and any(expect in e for e in errs), errs


def test_extension_keys_are_allowed_and_ignored_by_the_manifest():
    doc = mutated(lambda d: d.update({"x-note": "ok"}))
    assert dsl.validate(doc, DIR) == []
    assert dsl.to_manifest(doc) == MANIFEST


def _leak(doc):
    doc["hints"][0]["text"] += " The check is called san_exact."


SEMANTIC_CASES = [
    ("weights that do not sum to 1", _set(["scoring", "weights", "latency"], 0.2), "must sum to 1"),
    ("a fault that targets an unknown service", _set(["faults", 0, "targets"], ["api", "ghost"]), "unknown target service 'ghost'"),
    ("an assertion that observes an unknown service", _set(["assertions", 0, "check", "observes"], ["ghost"]), "unknown service 'ghost'"),
    ("a duplicated assertion id", lambda d: d["assertions"].append(copy.deepcopy(d["assertions"][0])), "duplicate id 'tls_handshake_ok'"),
    ("health_stable_10s that waits 5 s", _set(["assertions", 3, "check", "window_s"], 5), "promises 10 s"),
    ("tiers out of order", _set(["scoring", "tiers", "merit"], 0.95), "pass < merit < elite"),
    ("limits where full is not below zero", _set(["scoring", "limits", "mttr_s_full"], 400), "mttr_s_full must be below mttr_s_zero"),
    ("hints that are not increasing", _set(["hints", 1, "after_s"], 100), "strictly increasing"),
    ("two hints released at the same second", _set(["hints", 1, "after_s"], 180), "strictly increasing"),
    ("a hint that names a hidden assertion", _leak, "hidden, but named in text the participant sees"),
    ("a constraint enforced by nothing", _set(["tasks", 0, "constraints", 0, "enforced_by"], "assertion:ghost"), "unknown 'assertion:ghost'"),
    ("a confirmed assertion that does not exist", _set(["evidence", "independent_measurement", "confirm_assertions"], ["ghost"]),
     "unknown assertion 'ghost'"),
    ("a blast radius nobody can cause", lambda d: [f.update(targets=["api", "billing", "static", "admin"]) for f in d["faults"]],
     "can never differ"),
    ("no required assertion", lambda d: [a.update(kind="hidden") for a in d["assertions"]], "at least one must be required"),
    ("k3d provided with no files", _set(["env", "modes", "k3d"], {"status": "provided", "files": []}), "lists no files"),
    ("k3d not provided but listing files", _set(["env", "modes", "k3d"], {"status": "not_provided", "files": ["k3d.yaml"]}),
     "cannot claim what is not there"),
    ("a provided mode whose file is missing", _set(["env", "modes", "docker", "files"], ["docker/nope.yaml"]),
     "file does not exist: docker/nope.yaml"),
    ("an injector script that is missing", _set(["faults", 0, "injector", "script"], "scripts/nope.sh"),
     "file does not exist: scripts/nope.sh"),
]


@pytest.mark.parametrize("name,fn,expect", SEMANTIC_CASES, ids=[c[0] for c in SEMANTIC_CASES])
def test_the_semantic_rules_reject(name, fn, expect):
    doc = mutated(fn)
    assert dsl.schema_errors(doc) == [], "the case must get past the schema, or it tests the wrong layer"
    errs = dsl.validate(doc, DIR)
    assert any(expect in e for e in errs), errs


def test_a_document_the_schema_rejects_gets_no_semantic_errors_on_top():
    errs = dsl.validate({"dsl_version": "0"}, DIR)
    assert errs and not any("duplicate" in e or "unknown" in e for e in errs)


# ------------------------------------------------------------------ the manifest follows the DSL
def test_reordering_the_faults_changes_the_manifest():
    doc = mutated(lambda d: d["faults"].reverse())
    assert dsl.validate(doc, DIR) == []
    assert dsl.to_manifest(doc)["variants"] != MANIFEST["variants"]


def test_a_changed_weight_is_drift_against_the_pinned_manifest():
    doc = mutated(lambda d: d["scoring"]["weights"].update(latency=0.05, availability=0.30))
    assert dsl.validate(doc, DIR) == [] and dsl.to_manifest(doc) != MANIFEST


def test_without_an_independent_measurement_block_the_manifest_has_none():
    doc = mutated(lambda d: d["evidence"].pop("independent_measurement"))
    assert "independent_measurement" not in dsl.to_manifest(doc)


# ------------------------------------------------------------------ the command line
def _cli(*args):
    return subprocess.run([sys.executable, str(ROOT / "cfr_scenarios" / "dsl" / "cfr_dsl.py"), *args],
                          capture_output=True, text=True)


def test_cli_validates_and_checks_the_shipped_scenario():
    assert _cli("validate", str(SCENARIO)).returncode == 0
    r = _cli("manifest", str(SCENARIO), "--check", str(DIR / "manifest.json"))
    assert r.returncode == 0, r.stderr


def test_cli_exits_1_on_an_invalid_scenario_and_on_manifest_drift(tmp_path):
    bad = tmp_path / "scenario.yaml"
    bad.write_text(yaml.safe_dump(mutated(_set(["scoring", "weights", "latency"], 0.2))))
    r = _cli("validate", str(bad))
    assert r.returncode == 1 and "must sum to 1" in r.stderr
    stale = tmp_path / "manifest.json"
    stale.write_text(json.dumps({**MANIFEST, "version": "2"}))
    r = _cli("manifest", str(SCENARIO), "--check", str(stale))
    assert r.returncode == 1 and "DRIFT" in r.stderr


def test_cli_exits_2_unknown_when_a_dependency_is_missing(monkeypatch, capsys):
    def boom(_):
        raise dsl.DslUnavailable("PyYAML is not installed")
    monkeypatch.setattr(dsl, "load_yaml", boom)
    assert dsl.main(["validate", str(SCENARIO)]) == 2
    assert "UNKNOWN" in capsys.readouterr().err
