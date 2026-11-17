#!/usr/bin/env python3
"""Independent V1/V2/V3/V4 evidence verifier, without importing writer code."""
import argparse
import hashlib
import json
import os
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.igor_evidence_verifier import verify_chain as verify_evidence_chain


def verify_chain(db_path, tenant_id, expected_count, *, tamper=False):
    with sqlite3.connect(db_path, timeout=1.0) as conn:
        rows = conn.execute(
            "SELECT id, tenant_id, seq, record_type, payload_json, prev_hash, record_hash "
            "FROM evidence_records WHERE tenant_id=? ORDER BY seq", (tenant_id,)
        ).fetchall()
        if expected_count < 1 or len(rows) != expected_count:
            raise ValueError("record count mismatch")
        records = [{
            "id": row[0], "tenant_id": row[1], "seq": row[2],
            "record_type": row[3], "payload_json": row[4],
            "prev_hash": row[5], "record_hash": row[6],
        } for row in rows]
        valid, reason = verify_evidence_chain(records)
        if not valid:
            raise ValueError(reason)
        previous = rows[-1][6]
        if tamper:
            try:
                conn.execute(
                    "UPDATE evidence_records SET payload_json=? WHERE id=?",
                    ('{"tampered":true}', rows[0][0]),
                )
                conn.commit()
            except sqlite3.IntegrityError as exc:
                conn.rollback()
                if str(exc) != "evidence_records is append-only":
                    raise ValueError("unrelated database integrity failure") from exc
            except sqlite3.DatabaseError as exc:
                conn.rollback()
                raise ValueError("unrelated database write failure") from exc
            else:
                raise ValueError("append-only trigger did not block tamper")
        return {
            "status": "VERIFIED", "records": len(rows),
            "chain_root": previous, "tamper_blocked": bool(tamper),
        }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--tenant-id", required=True)
    p.add_argument("--expected-count", type=int, required=True)
    p.add_argument("--tamper-check", action="store_true")
    p.add_argument("--db", default=os.getenv("OLA_EG_DB_PATH", "/data/ola.db"))
    args = p.parse_args()
    try:
        result = verify_chain(args.db, args.tenant_id, args.expected_count,
                              tamper=args.tamper_check)
    except (ValueError, sqlite3.DatabaseError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "BLOCKED", "reason": str(exc)}), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
