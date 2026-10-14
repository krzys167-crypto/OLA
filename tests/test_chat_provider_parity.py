"""NINA conversation is provider-backed, never a substitute for an execution gate."""
import json
import uuid

import httpx
from sqlalchemy import select

from app.chat_runtime import chat
from app.database import SessionLocal
from app.models import EvidenceRecord, Tenant


def tenant():
    identity = str(uuid.uuid4())
    with SessionLocal() as db:
        db.add(Tenant(id=identity, name="chat_" + identity))
        db.commit()
    return identity


def rows(tenant_id):
    with SessionLocal() as db:
        return db.scalars(
            select(EvidenceRecord).where(EvidenceRecord.tenant_id == tenant_id)
        ).all()


def test_ollama_chat_records_real_provider_and_only_digest(monkeypatch):
    tenant_id = tenant()
    monkeypatch.setenv("OLA_CHAT_PROVIDER", "ollama")
    monkeypatch.setenv("OLA_CHAT_MODEL", "gemma4:cloud")
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
    def fake_post(url, *, json, timeout, **kwargs):
        assert url == "http://127.0.0.1:11434/api/chat"
        assert json["model"] == "gemma4:cloud"
        assert json["stream"] is False
        assert json["messages"][-1] == {"role": "user", "content": "hello local"}
        return httpx.Response(
            200, json={"message": {"role": "assistant", "content": "local response"},
                       "done": True},
            request=httpx.Request("POST", url),
        )
    monkeypatch.setattr(httpx, "post", fake_post)
    result = chat(tenant_id, [{"role": "user", "content": "hello local"}])
    assert result["status"] == "VERIFIED"
    assert result["scope"] == "CHAT_ONLY"
    assert result["provider"] == "ollama"
    assert result["model"] == "gemma4:cloud"
    assert result["message"] == "local response"
    assert result["evidence_id"]
    records = rows(tenant_id)
    assert len(records) == 1
    payload = json.loads(records[0].payload_json)
    assert payload["provider"] == "ollama"
    assert payload["scope"] == "CHAT_ONLY"
    assert payload["response_id"].startswith("ollama:")
    assert "hello local" not in records[0].payload_json
    assert "local response" not in records[0].payload_json


def test_missing_provider_and_bad_payload_block_no_false_evidence(monkeypatch):
    tenant_id = tenant()
    monkeypatch.setenv("OLA_CHAT_PROVIDER", "shell")
    assert chat(tenant_id, [{"role": "user", "content": "run cmd"}])["status"] == "BLOCK"
    monkeypatch.setenv("OLA_CHAT_PROVIDER", "ollama")
    assert chat(tenant_id, [{"role": "user", "content": "x" * 4001}])["status"] == "BLOCK"
    assert rows(tenant_id) == []


def test_unavailable_ollama_fail_closed_without_fake_chat(monkeypatch):
    tenant_id = tenant()
    monkeypatch.setenv("OLA_CHAT_PROVIDER", "ollama")
    def unreachable(url, **kwargs):
        raise httpx.ConnectError("host unreachable")
    monkeypatch.setattr(httpx, "post", unreachable)
    result = chat(tenant_id, [{"role": "user", "content": "are you online"}])
    assert result["status"] == "BLOCK"
    assert result["reason"] == "configured chat provider unavailable or response invalid"
    assert rows(tenant_id) == []


def test_openai_chat_optional_and_scope_is_chat_only(monkeypatch):
    tenant_id = tenant()
    monkeypatch.setenv("OLA_CHAT_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "CI_TEST_TOKEN_NOT_PRODUCTION")
    monkeypatch.setenv("OLA_CHAT_MODEL", "test-model")
    def fake_post(url, *, headers, json, timeout):
        assert url.endswith("/responses")
        assert headers["Authorization"] == "Bearer CI_TEST_TOKEN_NOT_PRODUCTION"
        assert json["model"] == "test-model"
        return httpx.Response(
            200,
            json={"id": "resp_test", "output_text": "hello from provider"},
            request=httpx.Request("POST", url),
        )
    monkeypatch.setattr(httpx, "post", fake_post)
    result = chat(tenant_id, [{"role": "user", "content": "hello"}])
    assert result["scope"] == "CHAT_ONLY"
    assert result["message"] == "hello from provider"
    assert "CI_TEST_TOKEN_NOT_PRODUCTION" not in str(result)
    assert "CI_TEST_TOKEN_NOT_PRODUCTION" not in str(rows(tenant_id)[0].payload_json)
