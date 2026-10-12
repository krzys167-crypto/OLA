#!/usr/bin/env python3
"""OFFLINE ONLY: reissue all OLA SQLite API keys for v2 credential hashing.

This is an explicit destructive credential rotation: previous client key text
WILL STOP WORKING. Preserve key_id/tenant_id for audit and 4-eyes approvals.
DO NOT run against a live database; stop every writer, take an external
snapshot, then run --apply. Never print/reveal tokens in console or CI logs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import sys

from app.api_key_crypto import hash_api_key

class RotationBlocked(RuntimeError):
    pass

def _safe_destination(path: Path, source: Path):
    path = path.absolute()
    if path == source or path.exists() or path.is_symlink():
        raise RotationBlocked("destination already exists or overlaps database")
    if not path.parent.is_dir():
        raise RotationBlocked("destination parent directory missing")
    return path

def _inventory(conn):
    check = conn.execute("PRAGMA integrity_check").fetchone()
    if not check or check[0] != "ok":
        raise RotationBlocked("database integrity_check failed")
    rows = conn.execute("SELECT id, tenant_id, key_hash FROM api_keys ORDER BY id").fetchall()
    if any(not isinstance(id_, str) or not isinstance(tenant, str)
           or not isinstance(digest, str) or len(digest) != 64
           for id_, tenant, digest in rows):
        raise RotationBlocked("malformed existing API-key inventory")
    return rows

def rotate(db_path: Path, output: Path, backup: Path, apply: bool, offline_confirmed: bool):
    db_path = db_path.absolute()
    if not db_path.is_file() or db_path.is_symlink():
        raise RotationBlocked("source database not a regular file")
    output = _safe_destination(output, db_path)
    backup = _safe_destination(backup, db_path)
    if output == backup:
        raise RotationBlocked("backup and token output must differ")
    if apply and (not offline_confirmed or os.name != "posix"):
        raise RotationBlocked("requires --runtime-stopped and POSIX 0600 permissions")
    db = sqlite3.connect(str(db_path), timeout=2)
    try:
        inventory = _inventory(db)
        if not apply:
            return {"status": "DRY_RUN", "keys": len(inventory),
                    "key_ids_preserved": True, "mutations": 0}
        if os.environ.get("OLA_API_KEY_PEPPER", "") == "":
            raise RotationBlocked("deployment pepper is not configured")
        # Assert the hash function and deployment pepper before any backup/write.
        hash_api_key("rotation-preflight")
        old_mode = os.umask(0o077)
        try:
            snapshot = sqlite3.connect(str(backup))
            try:
                db.backup(snapshot)
                snapshot.commit()
            finally:
                snapshot.close()
            os.chmod(backup, 0o600)
            # Existing writers must be stopped; abort if inventory changed after backup.
            db.execute("BEGIN EXCLUSIVE")
            current = db.execute("SELECT id,tenant_id,key_hash FROM api_keys ORDER BY id").fetchall()
            if current != inventory:
                raise RotationBlocked("concurrent key changes detected since backup")
            credentials = []
            rotated = []
            for id_, tenant_id, _ in inventory:
                secret = "ola2_" + secrets.token_urlsafe(48)
                digest = hash_api_key(secret)
                credentials.append({"key_id": id_, "tenant_id": tenant_id, "api_key": secret})
                rotated.append((digest, id_))
            receipt = {"schema": "ola-api-keys-v2/offline-reissue",
                       "keys": credentials, "number_of_keys": len(credentials)}
            fd = os.open(str(output), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as stream:
                    json.dump(receipt, stream, indent=2, sort_keys=True)
                    stream.write("\n")
                    stream.flush()
                    os.fsync(stream.fileno())
                for digest, id_ in rotated:
                    cursor = db.execute("UPDATE api_keys SET key_hash=? WHERE id=?", (digest, id_))
                    if cursor.rowcount != 1:
                        raise RotationBlocked("key row changed during reissue")
                db.commit()
            except BaseException:
                db.rollback()
                output.unlink(missing_ok=True)
                raise
        finally:
            os.umask(old_mode)
        # Never write raw tokens into logs. Owner must distribute securely and
        # erase the 0600 receipt after every client confirms credential rotation.
        return {"status": "ROTATED_OFFLINE", "keys": len(inventory),
                "key_ids_preserved": True, "backup_written": True,
                "receipt_written": True, "legacy_auth_fallback": False}
    finally:
        db.close()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--backup", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--runtime-stopped", action="store_true",
                        help="Operator asserts ALL OLA writers have been stopped")
    args = parser.parse_args()
    try:
        result = rotate(args.db,args.receipt,args.backup,args.apply,args.runtime_stopped)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (RotationBlocked, sqlite3.Error, OSError) as exc:
        print("BLOCKED: " + str(exc), file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
