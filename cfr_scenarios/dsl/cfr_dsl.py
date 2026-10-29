"""CFR scenario DSL v0: validate a scenario.yaml and generate the manifest the OLA server registers from it.

    python3 cfr_scenarios/dsl/cfr_dsl.py validate cfr_scenarios/certificate-apocalypse/scenario.yaml
    python3 cfr_scenarios/dsl/cfr_dsl.py manifest cfr_scenarios/certificate-apocalypse/scenario.yaml [--check manifest.json]

Two layers of checks, in this order, because the second is meaningless on a document the first rejects:
  1. scenario.schema.json (JSON Schema 2020-12): shape, types, ranges, per-fault-kind params.
  2. semantic rules JSON Schema cannot say: cross references (fault targets, asserted services, constraint owners),
     weights sum to 1, monotone limits and tiers, `health_stable_Ns` really waits N seconds, a mode that is not provided
     lists no files, a provided one lists files that exist, a hidden assertion is not named in any text the participant sees.

Exit codes: 0 valid / manifest identical, 1 invalid or the manifest drifted, 2 UNKNOWN (PyYAML or jsonschema is not installed,
so nothing could be checked: never a pass).
The manifest (cfr_scenarios/<id>/manifest.json) stays what the server pins by digest; this module only derives it, so the
DSL cannot silently change what a run is scored against.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

HERE = Path(__file__).resolve().parent
SCHEMA_PATH = HERE / "scenario.schema.json"
_HEALTH_STABLE = re.compile(r"^health_stable_(\d+)s$")


class DslUnavailable(Exception):
    """A dependency needed to check the document is missing: the result is UNKNOWN, not valid."""


def load_yaml(path: Path) -> Any:
    try:
        import yaml
    except ImportError as exc:
        raise DslUnavailable("PyYAML is not installed (pip install PyYAML)") from exc
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def load_schema() -> Dict[str, Any]:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def schema_errors(doc: Any) -> List[str]:
    try:
        from jsonschema import Draft202012Validator
    except ImportError as exc:
        raise DslUnavailable("jsonschema is not installed (pip install jsonschema)") from exc
    v = Draft202012Validator(load_schema())
    return sorted(f"{'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}" for e in v.iter_errors(doc))


def _dups(items: List[str]) -> List[str]:
    return sorted({x for x in items if items.count(x) > 1})


def _visible_texts(doc: Dict[str, Any]) -> List[str]:
    """Everything a participant can read before or during a run."""
    out = [doc["meta"]["title"], doc["meta"]["brief"]]
    for t in doc["tasks"]:
        out += [t["title"], t["brief"]] + [c["statement"] for c in t["constraints"] if c["visible"]]
    return out + [h["text"] for h in doc["hints"]]


def semantic_errors(doc: Dict[str, Any], root: Optional[Path] = None) -> List[str]:
    """Rules over a document that already passed the schema. `root` (the scenario directory) enables file checks."""
    errs: List[str] = []
    svc = [s["name"] for s in doc["services"]]
    asr = [a["id"] for a in doc["assertions"]]
    for what, ids in (("services", svc), ("faults", [f["id"] for f in doc["faults"]]), ("assertions", asr),
                      ("tasks", [t["id"] for t in doc["tasks"]]), ("hints", [h["id"] for h in doc["hints"]])):
        errs += [f"{what}: duplicate id {d!r}" for d in _dups(ids)]
    targeted = set()
    for f in doc["faults"]:
        targeted |= set(f["targets"])
        errs += [f"faults/{f['id']}: unknown target service {t!r}" for t in f["targets"] if t not in svc]
    if doc["scoring"]["weights"]["blast_radius"] > 0 and not set(svc) - targeted:
        errs.append("scoring: blast_radius is weighted but every service is a fault target, so it can never differ")
    if not any(a["kind"] == "required" for a in doc["assertions"]):
        errs.append("assertions: at least one must be required (nothing to pass otherwise)")
    for a in doc["assertions"]:
        errs += [f"assertions/{a['id']}: observes unknown service {s!r}" for s in a["check"]["observes"] if s not in svc]
        m = _HEALTH_STABLE.match(a["id"])
        if m and a["check"].get("window_s") != int(m.group(1)):
            errs.append(f"assertions/{a['id']}: the name promises {m.group(1)} s, check.window_s is {a['check'].get('window_s')}")
    sc = doc["scoring"]
    if abs(sum(sc["weights"].values()) - 1.0) > 1e-9:
        errs.append("scoring.weights must sum to 1")
    lim = sc["limits"]
    for name in ("latency_p95_ms", "mttr_s", "blast_radius"):
        if not lim[f"{name}_full"] < lim[f"{name}_zero"]:
            errs.append(f"scoring.limits: {name}_full must be below {name}_zero")
    t = sc["tiers"]
    if not t["pass"] < t["merit"] < t["elite"]:
        errs.append("scoring.tiers must satisfy pass < merit < elite")
    im = doc["evidence"].get("independent_measurement")
    if im:
        errs += [f"evidence.independent_measurement: confirms unknown assertion {a!r}"
                 for a in im["confirm_assertions"] if a not in asr]
    owners = set(sc["weights"]) | set(sc["penalties"])
    for tk in doc["tasks"]:
        for c in tk["constraints"]:
            kind, _, name = c["enforced_by"].partition(":")
            if (kind == "assertion" and name not in asr) or (kind == "scoring" and name not in owners):
                errs.append(f"tasks/{tk['id']}: constraint {c['statement']!r} is enforced by unknown {c['enforced_by']!r}")
    after = [h["after_s"] for h in doc["hints"]]
    if any(b <= a for a, b in zip(after, after[1:])):
        errs.append("hints: after_s must be strictly increasing (progressive disclosure)")
    text = "\n".join(_visible_texts(doc)).lower()
    errs += [f"assertions/{a['id']}: hidden, but named in text the participant sees"
             for a in doc["assertions"] if a["kind"] == "hidden" and a["id"].lower() in text]
    for name, mode in doc["env"]["modes"].items():
        if mode["status"] == "not_provided" and mode["files"]:
            errs.append(f"env.modes.{name}: not_provided, yet it lists files (a scenario cannot claim what is not there)")
        if mode["status"] == "provided" and not mode["files"]:
            errs.append(f"env.modes.{name}: provided, but lists no files")
    if root is not None:
        paths = [p for m in doc["env"]["modes"].values() for p in m["files"]]
        paths += [f["injector"]["script"] for f in doc["faults"]] + [doc["traffic"]["load"]["script"]]
        paths += [a["check"]["script"] for a in doc["assertions"]]
        if im:
            paths.append(im["witness"]["script"])
        errs += [f"file does not exist: {p}" for p in sorted(set(paths)) if not (Path(root) / p).is_file()]
    return errs


def validate(doc: Any, root: Optional[Path] = None) -> List[str]:
    errs = schema_errors(doc)
    return errs if errs else semantic_errors(doc, root)


def to_manifest(doc: Dict[str, Any]) -> Dict[str, Any]:
    """The manifest app/cfr.py registers (and pins by digest). `variants` keep the order of `faults`: the server picks a
    variant by index, so reordering faults is a new scenario version, not an edit."""
    sc = doc["scoring"]
    out: Dict[str, Any] = {
        "scenario_id": doc["meta"]["id"],
        "version": doc["meta"]["version"],
        "required_assertions": [a["id"] for a in doc["assertions"] if a["kind"] == "required"],
        "hidden_assertions": [a["id"] for a in doc["assertions"] if a["kind"] == "hidden"],
        "variants": [f["id"] for f in doc["faults"]],
        "scoring": {k: dict(sc[k]) for k in ("weights", "limits", "penalties", "tiers")},
    }
    im = doc["evidence"].get("independent_measurement")
    if im:                                           # absent stays absent: the manifest digest depends on it
        out["independent_measurement"] = {"required": im["required"], "confirm_assertions": list(im["confirm_assertions"]),
                                          "tolerance": dict(im["tolerance"])}
    return out


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="cfr_dsl.py")
    sub = p.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate")
    v.add_argument("scenario")
    m = sub.add_parser("manifest")
    m.add_argument("scenario")
    m.add_argument("--check", metavar="MANIFEST_JSON", help="exit 1 unless this file equals the generated manifest")
    a = p.parse_args(argv)
    path = Path(a.scenario)
    try:
        doc = load_yaml(path)
        errs = validate(doc, path.parent)
    except DslUnavailable as exc:
        print(f"UNKNOWN: {exc}", file=sys.stderr)
        return 2
    if errs:
        print("INVALID", file=sys.stderr)
        for e in errs:
            print(f"  {e}", file=sys.stderr)
        return 1
    if a.cmd == "validate":
        print(f"OK {doc['meta']['id']} v{doc['meta']['version']}")
        return 0
    generated = to_manifest(doc)
    if a.check:
        on_disk = json.loads(Path(a.check).read_text(encoding="utf-8"))
        if on_disk != generated:
            print(f"DRIFT: {a.check} differs from the manifest generated from {path}", file=sys.stderr)
            return 1
        print(f"OK {a.check} equals the generated manifest")
        return 0
    print(json.dumps(generated, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
