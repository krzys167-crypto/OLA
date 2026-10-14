#!/usr/bin/env python3
"""Export a clean Git app/policies inventory for local container byte checks."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app.execution_binding import capture_source, digest


def build(root=ROOT):
    if os.getenv("OLA_SOURCE_MODE", "git") != "git":
        raise ValueError("manifest generation requires Git source mode")
    source = capture_source(root)
    if source.get("status") != "LOCAL":
        raise ValueError("clean Git source required: " + source.get("reason", "unknown"))
    paths = subprocess.check_output(["git", "-C", str(root), "ls-tree", "-rz", "--name-only",
                                     "HEAD", "--", "app", "policies"]).split(b"\0")
    files = {p.decode(): hashlib.sha256((Path(root) / p.decode()).read_bytes()).hexdigest()
             for p in paths if p}
    if digest(files) != source["files_digest"] or capture_source(root) != source:
        raise ValueError("source changed while building inventory")
    return {"schema": "ola-local-build-v1", "source_sha": source["sha"], "files": files}


if __name__ == "__main__":
    manifest = build()
    (ROOT / "source-manifest.json").write_text(json.dumps(manifest, sort_keys=True) + "\n")
    print("BUILD_INVENTORY=LOCAL SOURCE_SHA=" + manifest["source_sha"] + " ATTESTATION=UNKNOWN")
