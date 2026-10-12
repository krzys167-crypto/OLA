"""Offline reissue cannot silently overwrite keys or discard tenant/key IDs."""
import json
import os
from pathlib import Path
import sqlite3

import pytest

from app.api_key_crypto import hash_api_key
from scripts.reissue_api_keys_v2 import RotationBlocked, rotate


def _db(tmp_path: Path) -> Path:
    path = tmp_path / "production-copy.db"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE api_keys (id TEXT PRIMARY KEY, tenant_id TEXT, key_hash TEXT UNIQUE)")
        db.executemany(
            "INSERT INTO api_keys VALUES (?,?,?)",
            [("key-1", "tenant-a", "1" * 64),
             ("key-2", "tenant-b", "2" * 64)],
        )
    return path


def test_dry_run_is_read_only_without_pepper(tmp_path, monkeypatch):
    monkeypatch.delenv("OLA_API_KEY_PEPPER", raising=False)
    db = _db(tmp_path)
    before = db.read_bytes()
    result = rotate(db, tmp_path/"tokens.json", tmp_path/"safe.db",False,False)
    assert result == {
        "status":"DRY_RUN","keys":2,"key_ids_preserved":True,"mutations":0}
    assert db.read_bytes() == before
    assert not (tmp_path/"tokens.json").exists()
    assert not (tmp_path/"safe.db").exists()


def test_rotation_requires_explicit_offline_operator_gate(tmp_path, monkeypatch):
    monkeypatch.setenv("OLA_API_KEY_PEPPER", "P" * 64)
    db = _db(tmp_path)
    with pytest.raises(RotationBlocked):
        rotate(db,tmp_path/"tokens.json",tmp_path/"backup.db",True,False)


def test_rotation_preserves_legacy_backup_and_issues_new_keys(tmp_path, monkeypatch):
    monkeypatch.setenv("OLA_API_KEY_PEPPER", "P" * 64)
    db = _db(tmp_path)
    result = rotate(db,tmp_path/"tokens.json",tmp_path/"backup.db",True,True)
    assert result["status"] == "ROTATED_OFFLINE"
    assert result["legacy_auth_fallback"] is False
    assert (tmp_path/"tokens.json").stat().st_mode & 0o777 == 0o600
    assert (tmp_path/"backup.db").stat().st_mode & 0o777 == 0o600
    rows_before = sqlite3.connect(tmp_path/"backup.db").execute("SELECT * FROM api_keys ORDER BY id").fetchall()
    rows_after = sqlite3.connect(db).execute("SELECT * FROM api_keys ORDER BY id").fetchall()
    assert [(a,b) for a,b,_ in rows_after] == [(a,b) for a,b,_ in rows_before]
    assert [v for _,_,v in rows_before] == ["1"*64,"2"*64]
    receipt = json.loads((tmp_path/"tokens.json").read_text())
    assert len(receipt["keys"]) == 2
    assert all(row["api_key"].startswith("ola2_") for row in receipt["keys"])
    assert len({row["api_key"] for row in receipt["keys"]}) == 2
    assert [hash_api_key(row["api_key"]) for row in receipt["keys"]] == [v for _,_,v in rows_after]


def test_refuse_existing_sensitive_receipt_without_mutation(tmp_path, monkeypatch):
    monkeypatch.setenv("OLA_API_KEY_PEPPER", "P" * 64)
    db = _db(tmp_path)
    sensitive = tmp_path / "tokens.json"
    sensitive.write_text("do not overwrite")
    with pytest.raises(RotationBlocked):
        rotate(db,sensitive,tmp_path/"backup.db",True,True)
    assert sensitive.read_text() == "do not overwrite"
    assert not (tmp_path/"backup.db").exists()
