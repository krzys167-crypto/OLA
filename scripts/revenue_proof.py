#!/usr/bin/env python3
"""Print the computed first-payment proof (app/revenue_proof.py) for every tenant, or for one with --tenant.

Reads only the database named by OLA_EG_DB_PATH. Exit 0 when at least one tenant is PROVEN, 3 when none is."""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import select  # noqa: E402

from app.database import SessionLocal  # noqa: E402
from app.models import Tenant  # noqa: E402
from app.revenue_proof import revenue_proof  # noqa: E402


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tenant", help="tenant id (default: every tenant)")
    args = parser.parse_args(argv)
    if args.tenant:
        tenants = [args.tenant]
    else:
        with SessionLocal() as db:
            tenants = list(db.scalars(select(Tenant.id)))
    reports = {tenant: revenue_proof(tenant) for tenant in tenants}
    print(json.dumps({"proven": [t for t, r in reports.items() if r["status"] == "PROVEN"], "tenants": reports},
                     indent=2, sort_keys=True))
    return 0 if any(r["status"] == "PROVEN" for r in reports.values()) else 3


if __name__ == "__main__":
    sys.exit(main())
