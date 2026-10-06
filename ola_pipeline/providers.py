"""LLM providers: ollama-local, ollama-cloud, openai. Anything else is refused.

Ollama uses its official native API (/api/version, /api/tags, /api/chat). Each execution
performs a preflight (version + model/digest resolution) and returns the observations as a
runtime proof. No mock lives here: a test double is a separate HTTP server in tests/ that
declares itself via its version string, and the Gate rejects it unless policy allows it.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import os
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from .config import ProviderConfig
from .errors import (ConfigError, ModelUnresolved, ProviderError, ProviderTimeout,
                     ProviderUnavailable, UnknownProviderError)
from .redact import scrub
from .verify import KNOWN_PROVIDERS

def _is_loopback(host: str) -> bool:
    """localhost, 127.0.0.0/8, ::1 (also as an IPv4-mapped address). Parsed, not string-matched."""
    h = (host or "").strip().lower().rstrip(".")
    if h == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_loopback


@dataclass
class GenerationResult:
    text: str
    runtime_proof: Dict[str, Any]
    model_digest: Optional[str]
    resolved_model: str


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A 30x would re-send the Authorization header and the prompt body to wherever it points."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _http(method: str, url: str, body: Optional[dict], headers: Dict[str, str],
          timeout: float, secrets=()) -> Dict[str, Any]:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise ConfigError(f"unsupported URL scheme {parts.scheme!r} (only http and https)")
    if "Authorization" in headers and parts.scheme != "https" and not _is_loopback(parts.hostname or ""):
        raise ConfigError("refusing to send credentials over plain http to a non-loopback host")
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json", **headers})
    host = parts.hostname or ""
    opener = (urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)
              if _is_loopback(host) else urllib.request.build_opener(_NoRedirect))
    path = urlsplit(url).path
    try:
        with opener.open(req, timeout=timeout) as r:
            raw = r.read()
    except urllib.error.HTTPError as e:
        raise ProviderError(f"HTTP {e.code} from {path}") from None
    except urllib.error.URLError as e:
        if isinstance(e.reason, (socket.timeout, TimeoutError)):
            raise ProviderTimeout(f"timeout calling {path}") from None
        raise ProviderUnavailable(
            scrub(f"cannot reach {host}: {type(e.reason).__name__}", secrets)) from None
    except (socket.timeout, TimeoutError):
        raise ProviderTimeout(f"timeout calling {path}") from None
    except http.client.HTTPException as e:
        raise ProviderError(f"protocol error: {type(e).__name__}") from None
    except OSError as e:
        raise ProviderUnavailable(scrub(f"cannot reach {host}: {type(e).__name__}", secrets)) from None
    try:
        obj = json.loads(raw)
    except ValueError:
        raise ProviderError(f"non-JSON response from {path}") from None
    if not isinstance(obj, dict):
        raise ProviderError(f"unexpected JSON shape from {path}")
    return obj


class LLMProvider:
    def __init__(self, cfg: ProviderConfig):
        self.cfg = cfg

    def execute(self, messages: List[Dict[str, str]], json_mode: bool = False) -> GenerationResult:
        raise NotImplementedError


class OllamaProvider(LLMProvider):
    def _headers(self) -> Dict[str, str]:
        if self.cfg.provider != "ollama-cloud":
            return {}
        key = os.environ.get(self.cfg.effective_key_env(), "")
        if not key:
            raise ProviderUnavailable(f"API key env {self.cfg.effective_key_env()} is not set")
        return {"Authorization": f"Bearer {key}"}

    @staticmethod
    def _candidates(wanted: str) -> set:
        return {wanted} | ({wanted + ":latest"} if ":" not in wanted else set())

    def execute(self, messages, json_mode=False) -> GenerationResult:
        cfg = self.cfg
        base = cfg.effective_base_url()
        headers = self._headers()
        secrets = cfg.known_secrets()
        pre_t = min(cfg.timeout_s, 15.0)

        version: Optional[str] = None
        try:
            v = _http("GET", base + "/api/version", None, headers, pre_t, secrets)
            if not isinstance(v.get("version"), str) or not v["version"]:
                raise ProviderError("malformed /api/version response")
            version = v["version"]
        except ProviderError:
            if cfg.provider == "ollama-local":
                raise  # local runtime MUST answer /api/version
            version = None  # cloud: tolerated, recorded as null (UNTESTED assumption)

        tags = _http("GET", base + "/api/tags", None, headers, pre_t, secrets)
        models = tags.get("models")
        if not isinstance(models, list):
            raise ProviderError("malformed /api/tags response")
        cands = self._candidates(cfg.model)
        match = next((m for m in models if isinstance(m, dict)
                      and (m.get("name") in cands or m.get("model") in cands)), None)
        if match is None:
            raise ModelUnresolved(f"model {cfg.model!r} not present on endpoint")
        resolved = match.get("name") or match.get("model") or cfg.model
        digest = match.get("digest") if isinstance(match.get("digest"), str) and match.get("digest") else None

        body: Dict[str, Any] = {"model": cfg.model, "messages": messages, "stream": False,
                                "options": {"temperature": cfg.temperature}}
        if cfg.seed is not None:
            body["options"]["seed"] = cfg.seed
        if cfg.max_tokens is not None:
            body["options"]["num_predict"] = cfg.max_tokens
        if json_mode:
            body["format"] = "json"
        if cfg.think is not None:
            body["think"] = cfg.think
        resp = _http("POST", base + "/api/chat", body, headers, cfg.timeout_s, secrets)

        msg = resp.get("message")
        text = msg.get("content") if isinstance(msg, dict) else None
        if not isinstance(text, str):
            raise ProviderError("missing message.content in /api/chat response")
        if resp.get("done") is not True:
            raise ProviderError("generation not marked done")
        accepted = cands | {x for x in (resolved, match.get("model")) if isinstance(x, str)}
        if not isinstance(resp.get("model"), str) or resp.get("model") not in accepted:
            raise ProviderError("response model does not match requested model")
        kind = "TEST_DOUBLE" if "test-double" in (version or "").lower() else "OLLAMA_OBSERVED"
        proof = {
            "kind": kind, "provider": cfg.provider, "endpoint": cfg.public_endpoint(),
            "ollama_version": version, "requested_model": cfg.model, "resolved_model": resolved,
            "model_digest": digest, "response_model": resp.get("model"), "done": True,
            "done_reason": resp.get("done_reason"), "created_at": resp.get("created_at"),
            "eval_count": resp.get("eval_count"), "prompt_eval_count": resp.get("prompt_eval_count"),
            "total_duration_ns": resp.get("total_duration"),
            "think_requested": cfg.think,
            "thinking_chars": len(msg["thinking"]) if isinstance(msg.get("thinking"), str) else 0,
        }
        return GenerationResult(text, proof, digest, resolved)


class OpenAIProvider(LLMProvider):
    def execute(self, messages, json_mode=False) -> GenerationResult:
        cfg = self.cfg
        key = os.environ.get(cfg.effective_key_env(), "")
        if not key:
            raise ProviderUnavailable(f"API key env {cfg.effective_key_env()} is not set")
        headers = {"Authorization": f"Bearer {key}"}
        base = cfg.effective_base_url()
        secrets = (key,)
        m = _http("GET", f"{base}/v1/models/{cfg.model}", None, headers, min(cfg.timeout_s, 15.0), secrets)
        if m.get("id") != cfg.model:
            raise ModelUnresolved(f"model {cfg.model!r} not confirmed by endpoint")
        body: Dict[str, Any] = {"model": cfg.model, "messages": messages, "temperature": cfg.temperature}
        if cfg.seed is not None:
            body["seed"] = cfg.seed
        if cfg.max_tokens is not None:
            body["max_tokens"] = cfg.max_tokens
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        resp = _http("POST", base + "/v1/chat/completions", body, headers, cfg.timeout_s, secrets)
        try:
            choice = resp["choices"][0]
            text = choice["message"]["content"]
        except (KeyError, IndexError, TypeError):
            raise ProviderError("malformed chat.completions response") from None
        if not isinstance(text, str):
            raise ProviderError("missing message content")
        if choice.get("finish_reason") not in ("stop",):
            raise ProviderError(f"unexpected finish_reason: {choice.get('finish_reason')!r}")
        proof = {
            "kind": "OPENAI_OBSERVED", "provider": cfg.provider, "endpoint": cfg.public_endpoint(),
            "requested_model": cfg.model, "response_model": resp.get("model"),
            "response_id": resp.get("id"), "system_fingerprint": resp.get("system_fingerprint"),
            "finish_reason": choice.get("finish_reason"), "usage": resp.get("usage"),
            "created": resp.get("created"),
        }
        return GenerationResult(text, proof, None, cfg.model)  # OpenAI exposes no model digest


def build_provider(cfg: ProviderConfig) -> LLMProvider:
    if cfg.provider not in KNOWN_PROVIDERS:
        raise UnknownProviderError(f"unknown provider: {cfg.provider!r}")
    if not cfg.model:
        raise ConfigError("model is not configured (no default model by design)")
    if not cfg.effective_base_url():
        raise ConfigError("base_url is not configured")
    if cfg.provider == "openai":
        return OpenAIProvider(cfg)
    return OllamaProvider(cfg)
