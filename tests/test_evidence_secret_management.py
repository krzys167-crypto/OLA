import base64
import json

import pytest

from app.evidence_v4 import (
    ACTIVE_KEY_ENV,
    KEYRING_ENV,
    InvalidKeyringError,
    Keyring,
    MissingKeyError,
    UnknownKeyError,
    load_keyring,
)


pytestmark = pytest.mark.secret_management


def test_missing_external_keyring_fails_closed(monkeypatch):
    monkeypatch.delenv(KEYRING_ENV, raising=False)
    monkeypatch.delenv(ACTIVE_KEY_ENV, raising=False)
    with pytest.raises(MissingKeyError):
        load_keyring()


def test_missing_active_key_id_fails_closed(monkeypatch):
    key = base64.b64encode(b"s" * 32).decode()
    monkeypatch.setenv(KEYRING_ENV, json.dumps({"k1": key}))
    monkeypatch.delenv(ACTIVE_KEY_ENV, raising=False)
    with pytest.raises(MissingKeyError):
        load_keyring()


def test_active_key_must_exist_in_injected_keyring(monkeypatch):
    key = base64.b64encode(b"s" * 32).decode()
    monkeypatch.setenv(KEYRING_ENV, json.dumps({"k1": key}))
    monkeypatch.setenv(ACTIVE_KEY_ENV, "missing")
    with pytest.raises(UnknownKeyError):
        load_keyring()


def test_short_injected_key_is_rejected(monkeypatch):
    key = base64.b64encode(b"short").decode()
    monkeypatch.setenv(KEYRING_ENV, json.dumps({"k1": key}))
    monkeypatch.setenv(ACTIVE_KEY_ENV, "k1")
    with pytest.raises(InvalidKeyringError):
        load_keyring()


def test_duplicate_key_ids_in_secret_payload_are_rejected(monkeypatch):
    first = base64.b64encode(b"a" * 32).decode()
    second = base64.b64encode(b"b" * 32).decode()
    monkeypatch.setenv(KEYRING_ENV, '{"k1":"' + first + '","k1":"' + second + '"}')
    monkeypatch.setenv(ACTIVE_KEY_ENV, "k1")
    with pytest.raises(InvalidKeyringError):
        load_keyring()


def test_key_material_is_not_exposed_by_keyring_repr():
    secret = b"never-print-this-key-material-32bytes"
    ring = Keyring(keys={"private-key-id": secret}, active_key_id="private-key-id")
    assert secret.decode() not in repr(ring)
