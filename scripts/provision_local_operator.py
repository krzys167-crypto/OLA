"""Issue a high-entropy operator key for an existing, configured OLA tenant runtime.

Explicit operator-only, local invocation:
    docker exec ola-cc-preview python -m scripts.provision_local_operator

The exact pepper from the server environment MUST exist; this command does not
create or print a pepper, migrate legacy SHA256 hashes or repair a deployment.
The raw credential is printed once to the local terminal and only its v2 KDF
digest is stored in SQLite. Never run this in CI, log collectors or public shells.
"""
from __future__ import annotations

import argparse
import secrets
import sys
import uuid

from sqlalchemy import select

from app.api_key_crypto import KeyConfigurationError, hash_api_key
from app.database import SessionLocal
from app.models import ApiKey, Tenant

DEFAULT_NAME = "zbook-preview-operator"


def issue_operator_key(tenant_name: str = DEFAULT_NAME) -> tuple[str, str]:
    """Create one new tenant+key; reject reuse of an existing named tenant."""
    if not isinstance(tenant_name, str) or not 1 <= len(tenant_name) <= 80:
        raise ValueError("tenant name length invalid")
    if not all(ch.isascii() and (ch.isalnum() or ch in "-_") for ch in tenant_name):
        raise ValueError("tenant name may contain only ASCII letters, numbers, hyphen, underscore")
    raw_key = "ola2_" + secrets.token_urlsafe(40)
    digest = hash_api_key(raw_key)  # fail-closed if the deployment pepper is absent

    with SessionLocal() as db:
        if db.scalar(select(Tenant.id).where(Tenant.name == tenant_name)):
            raise ValueError("tenant already exists: no new credential issued")
        tenant = Tenant(id=str(uuid.uuid4()), name=tenant_name)
        key = ApiKey(id=str(uuid.uuid4()), tenant_id=tenant.id, key_hash=digest)
        db.add_all([tenant, key])
        db.commit()
        return tenant.id, raw_key


def main() -> int:
    parser = argparse.ArgumentParser(description="Issue a local OLA API key; raw secret is displayed once.")
    parser.add_argument("--tenant-name", default=DEFAULT_NAME)
    args = parser.parse_args()
    try:
        tenant_id, secret = issue_operator_key(args.tenant_name)
    except (ValueError, KeyConfigurationError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 2
    print("OLA_OPERATOR_KEY_CREATED")
    print("TENANT_ID: " + tenant_id)
    print("X_API_KEY_ONCE: " + secret)
    print("Copy the key into OLA Command Center / SETTINGS and verify it.")
    print("The raw key cannot be recovered later; rotate via a controlled operation.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
