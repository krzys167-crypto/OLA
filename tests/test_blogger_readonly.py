import hashlib
import json

import httpx
import pytest

from app.blogger_adapter import BloggerAdapterError, get_blog_metadata
from app.hashchain import GENESIS_HASH, compute_record_hash, canonical_json
from app import blogger_capability as capability


class FakeClient:
    def __init__(self, response=None, error=None):
        self.response, self.error, self.calls = response, error, []

    def get(self, url, headers):
        self.calls.append((url, headers))
        if self.error:
            raise self.error
        return self.response


def response(status=200, data=None, headers=None):
    request = httpx.Request("GET", "https://www.googleapis.com/blogger/v3/blogs/123")
    return httpx.Response(status, json=data, headers=headers or {"content-type":"application/json"},
                          request=request)


def test_adapter_reads_only_fixed_blogger_endpoint_and_hashes_result():
    client = FakeClient(response(data={"id":"123","name":"Example","url":"https://example.blogspot.com/"}))
    result = get_blog_metadata("123", api_key="test-key", client=client)
    assert result["success"] is True
    assert result["operation"] == "blogs.get"
    assert result["blog_id"] == "123"
    assert result["result_sha256"]
    assert client.calls[0][0] == "https://www.googleapis.com/blogger/v3/blogs/123"
    assert client.calls[0][1]["X-Goog-Api-Key"] == "test-key"


def test_adapter_rejects_invalid_blog_id_before_network():
    client = FakeClient(response())
    with pytest.raises(BloggerAdapterError, match="INVALID_BLOG_ID"):
        get_blog_metadata("../123", api_key="test-key", client=client)
    assert client.calls == []


def test_adapter_rejects_upstream_identity_mismatch():
    client = FakeClient(response(data={"id":"999","url":"https://example.blogspot.com/"}))
    with pytest.raises(BloggerAdapterError, match="UPSTREAM_IDENTITY_MISMATCH"):
        get_blog_metadata("123", api_key="test-key", client=client)


def test_adapter_rejects_non_https_blog_url():
    client = FakeClient(response(data={"id":"123","url":"http://example.com/"}))
    with pytest.raises(BloggerAdapterError, match="UPSTREAM_INVALID_BLOG_URL"):
        get_blog_metadata("123", api_key="test-key", client=client)


def test_adapter_maps_not_found_without_returning_upstream_body():
    client = FakeClient(response(status=404, data={"error":{"message":"private upstream detail"}}))
    with pytest.raises(BloggerAdapterError) as exc:
        get_blog_metadata("123", api_key="test-key", client=client)
    assert exc.value.code == "BLOG_NOT_FOUND"
    assert "private upstream detail" not in str(exc.value)


def _append_factory(tenant):
    records = []
    def append(tenant_id, record_type, payload):
        seq = len(records)
        previous = records[-1]["record_hash"] if records else GENESIS_HASH
        payload_json = canonical_json(payload)
        record_hash = compute_record_hash(tenant_id, seq, previous, payload_json, record_type)
        records.append({"id":str(seq),"tenant_id":tenant_id,"seq":seq,"record_type":record_type,
                        "payload_json":payload_json,"prev_hash":previous,"record_hash":record_hash})
    return records, append


def test_capability_records_and_verifies_success_but_requires_human_review(monkeypatch):
    records, append = _append_factory("tenant-1")
    monkeypatch.setattr(capability, "append_evidence", append)
    monkeypatch.setattr(capability, "load_chain", lambda tenant_id: records)
    def fake_adapter(blog_id):
        result = {"success":True,"blog_id":blog_id,"operation":"blogs.get","blog_url":"https://example.com/"}
        result["result_sha256"] = capability._digest_result(result)
        return result
    out = capability.run_blogger_metadata("tenant-1", "123", adapter=fake_adapter)
    assert out["status"] == "REVIEW_REQUIRED"
    assert out["human_gate"] == "REVIEW_REQUIRED"
    assert out["execution"] == "NOT_PERFORMED"
    assert out["verification"]["status"] == "VERIFIED"
    assert len(records) == 3


def test_capability_blocks_bad_blog_id_without_evidence_or_network(monkeypatch):
    records, append = _append_factory("tenant-1")
    monkeypatch.setattr(capability, "append_evidence", append)
    called = []
    out = capability.run_blogger_metadata("tenant-1", "https://evil.example", adapter=lambda x: called.append(x))
    assert out["status"] == "BLOCK"
    assert records == []
    assert called == []


def test_semantic_verifier_rejects_tampered_result_digest(monkeypatch):
    records, append = _append_factory("tenant-1")
    result = {"success":True,"blog_id":"123","operation":"blogs.get","blog_url":"https://example.com/",
              "result_sha256":"0"*64}
    append("tenant-1", capability.START, {"run_id":"r1","blog_id":"123","tool":capability.TOOL_NAME})
    append("tenant-1", capability.RESULT, {"run_id":"r1","blog_id":"123","operation":"blogs.get","result":result})
    append("tenant-1", capability.END, {"run_id":"r1","blog_id":"123","status":"REVIEW_REQUIRED"})
    verdict = capability.verify_blogger_evidence(records,"r1","123")
    assert verdict["status"] == "BLOCK"
    assert verdict["checks"]["result_digest"] is False
