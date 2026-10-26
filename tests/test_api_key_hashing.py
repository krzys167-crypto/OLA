import hashlib
import uuid

import pytest
from fastapi import HTTPException

from app.api_key_hashing import api_key_fingerprint
from app.database import SessionLocal
from app.main import identity_from_key
from app.models import ApiKey, Tenant


def test_hash_is_keyed_and_not_raw_sha256(monkeypatch):
    monkeypatch.setenv("OLA_API_KEY_PEPPER", "test-only-secret-0123456789abcdef-abcdefgh")
    result = api_key_fingerprint("abc")
    assert len(result) == 64
    assert result != hashlib.sha256(b"abc").hexdigest()
    assert result == hashlib.scrypt(b"abc", salt=b"test-only-secret-0123456789abcdef-abcdefgh",
                                   n=1 << 14, r=8, p=1, maxmem=64 * 1024 * 1024,
                                   dklen=32).hex()


def test_pepper_required_fail_closed(monkeypatch):
    monkeypatch.delenv("OLA_API_KEY_PEPPER", raising=False)
    with pytest.raises(RuntimeError, match="not configured"):
        api_key_fingerprint("key")


def test_pepper_change_invalidates_old_fingerprint(monkeypatch):
    monkeypatch.setenv("OLA_API_KEY_PEPPER", "test-only-secret-0123456789abcdef-abcdefgh")
    first = api_key_fingerprint("test-key")
    monkeypatch.setenv("OLA_API_KEY_PEPPER", "another-test-secret-0123456789abcdef-abcdefgh")
    assert api_key_fingerprint("test-key") != first


def test_unkeyed_legacy_key_is_not_accepted(monkeypatch):
    monkeypatch.setenv("OLA_API_KEY_PEPPER", "test-only-secret-0123456789abcdef-abcdefgh")
    legacy_key = f"old-key-{uuid.uuid4()}"
    tenant_id = str(uuid.uuid4())
    with SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name="legacy-rejection"))
        db.commit()
        db.add(ApiKey(id=str(uuid.uuid4()), tenant_id=tenant_id,
                      key_hash=hashlib.sha256(legacy_key.encode()).hexdigest()))
        db.commit()
    with pytest.raises(HTTPException) as exc:
        identity_from_key(legacy_key)
    assert exc.value.status_code == 401


def test_missing_pepper_rejects_api_auth_even_if_db_has_key(monkeypatch):
    monkeypatch.delenv("OLA_API_KEY_PEPPER", raising=False)
    with pytest.raises(HTTPException) as exc:
        identity_from_key("any-key")
    assert exc.value.status_code == 503


def test_oversized_key_rejected_before_expensive_hash(monkeypatch):
    from app import api_key_hashing as hashing
    monkeypatch.setenv("OLA_API_KEY_PEPPER", "test-only-secret-0123456789abcdef-abcdefgh")
    def fail_if_hashed(*args, **kwargs):
        raise AssertionError("scrypt must not run for oversized key")
    monkeypatch.setattr(hashing.hashlib, "scrypt", fail_if_hashed)
    with pytest.raises(ValueError, match="too long"):
        hashing.api_key_fingerprint("A" * 513)
    with pytest.raises(HTTPException) as exc:
        identity_from_key("A" * 513)
    assert exc.value.status_code == 401


def test_scrypt_capacity_fails_closed_without_waiting(monkeypatch):
    from app import api_key_hashing as hashing
    monkeypatch.setenv("OLA_API_KEY_PEPPER", "test-only-secret-0123456789abcdef-abcdefgh")
    class BusySlots:
        def acquire(self, *, blocking):
            assert blocking is False
            return False
        def release(self):
            raise AssertionError("unacquired slot must never be released")
    monkeypatch.setattr(hashing, "_SCRYPT_SLOTS", BusySlots())
    with pytest.raises(RuntimeError, match="capacity"):
        hashing.api_key_fingerprint("candidate")


def test_scrypt_slot_released_on_hash_error(monkeypatch):
    from app import api_key_hashing as hashing
    monkeypatch.setenv("OLA_API_KEY_PEPPER", "test-only-secret-0123456789abcdef-abcdefgh")
    class Slots:
        released = False
        def acquire(self, *, blocking):
            assert blocking is False
            return True
        def release(self):
            self.released = True
    slots = Slots()
    monkeypatch.setattr(hashing, "_SCRYPT_SLOTS", slots)
    def fail(*args, **kwargs):
        raise RuntimeError("cryptographic failure")
    monkeypatch.setattr(hashing.hashlib, "scrypt", fail)
    with pytest.raises(RuntimeError, match="cryptographic failure"):
        hashing.api_key_fingerprint("candidate")
    assert slots.released is True
