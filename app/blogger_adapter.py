"""Read-only Google Blogger API v3 adapter. Only blogs.get is exposed."""
from __future__ import annotations
import hashlib, json, os, re, time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit
import httpx

ADAPTER_VERSION = "1.0.0"
BASE_URL = "https://www.googleapis.com/blogger/v3/blogs/"
BLOG_ID_RE = re.compile(r"^[0-9]{1,32}$")
MAX_BODY_BYTES = 65_536

class BloggerAdapterError(RuntimeError):
    def __init__(self, code: str, http_status: int | None = None):
        self.code, self.http_status = code, http_status
        super().__init__(code)

def _digest(value: dict[str, Any]) -> str:
    body = {k: v for k, v in value.items() if k != "result_sha256"}
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode()).hexdigest()

def _valid_blog_url(value: Any) -> bool:
    if not isinstance(value, str) or len(value) > 2048: return False
    try:
        p = urlsplit(value)
        return (p.scheme == "https" and bool(p.hostname) and p.username is None and p.password is None
                and p.port in (None, 443) and not p.query and not p.fragment
                and not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", p.hostname)
                and p.hostname.lower() != "localhost")
    except ValueError:
        return False

def get_blog_metadata(blog_id: str, *, api_key: str | None = None,
                      client: httpx.Client | None = None) -> dict[str, Any]:
    if not isinstance(blog_id, str) or not BLOG_ID_RE.fullmatch(blog_id):
        raise BloggerAdapterError("INVALID_BLOG_ID")
    key = api_key if api_key is not None else os.getenv("GOOGLE_BLOGGER_API_KEY")
    if not isinstance(key, str) or not key.strip() or len(key) > 512:
        raise BloggerAdapterError("API_KEY_NOT_CONFIGURED")
    owns = client is None
    http = client or httpx.Client(timeout=httpx.Timeout(connect=2, read=5, write=2, pool=2),
        follow_redirects=False, trust_env=False)
    headers = {"Accept": "application/json", "X-Goog-Api-Key": key.strip()}
    try:
        response = None
        for attempt in range(3):
            try:
                request = http.build_request("GET", BASE_URL + blog_id, headers=headers)
                response = http.send(request, stream=True)
            except (httpx.TimeoutException, httpx.TransportError):
                if attempt == 2: raise BloggerAdapterError("UPSTREAM_UNAVAILABLE") from None
                time.sleep(0.1 * (attempt + 1)); continue
            if response.status_code in (429, 500, 502, 503, 504) and attempt < 2:
                time.sleep(0.1 * (attempt + 1)); continue
            break
        status = response.status_code
        if status != 200:
            code = {400:"UPSTREAM_BAD_REQUEST",401:"UPSTREAM_UNAUTHORIZED",403:"UPSTREAM_FORBIDDEN",
                    404:"BLOG_NOT_FOUND",429:"UPSTREAM_RATE_LIMITED"}.get(status,"UPSTREAM_ERROR")
            raise BloggerAdapterError(code, status)
        if "application/json" not in response.headers.get("content-type","").lower():
            response.close()
            raise BloggerAdapterError("UPSTREAM_INVALID_CONTENT_TYPE", status)
        declared = response.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > MAX_BODY_BYTES:
            response.close()
            raise BloggerAdapterError("UPSTREAM_RESPONSE_TOO_LARGE", status)
        chunks = bytearray()
        try:
            for chunk in response.iter_bytes():
                chunks.extend(chunk)
                if len(chunks) > MAX_BODY_BYTES:
                    raise BloggerAdapterError("UPSTREAM_RESPONSE_TOO_LARGE", status)
        finally:
            response.close()
        try: data = json.loads(chunks)
        except (ValueError, UnicodeDecodeError): raise BloggerAdapterError("UPSTREAM_INVALID_JSON", status) from None
        if not isinstance(data, dict) or str(data.get("id","")) != blog_id:
            raise BloggerAdapterError("UPSTREAM_IDENTITY_MISMATCH", status)
        blog_url = data.get("url")
        if not _valid_blog_url(blog_url): raise BloggerAdapterError("UPSTREAM_INVALID_BLOG_URL", status)
        result = {"success":True,"provider":"google_blogger","operation":"blogs.get","blog_id":blog_id,
                  "blog_url":blog_url,"verified":True,"http_status":status,
                  "request_id":response.headers.get("x-request-id"),
                  "timestamp":datetime.now(timezone.utc).isoformat(),"error":None,
                  "adapter_version":ADAPTER_VERSION}
        if isinstance(data.get("name"),str) and len(data["name"]) <= 512: result["blog_name"] = data["name"]
        result["result_sha256"] = _digest(result)
        return result
    finally:
        if owns: http.close()
