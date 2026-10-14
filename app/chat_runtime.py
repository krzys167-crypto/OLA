"""NINA conversation via the configured provider, distinct from execution approval.

Supported: local / cloud Ollama via /api/chat and OpenAI Responses API.
The assistant NEVER invokes local workstation actions from a chat message.
A successful chat is not an IGOR verification or release authorization.
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Any

import httpx

from .hashchain import canonical_json

SYSTEM_PROMPT = (
    "You are NINA, a precise OLA DI-OS assistant. "
    "Never assert a command was executed from conversation alone. "
    "An operation is only attempted through the separate policy-controlled "
    "/nina-run or opt-in Local Executor interface. "
    "Never claim a production release without signed source and human gate."
)
MAX_HISTORY = 20
MAX_MESSAGE_CHARS = 4000
ALLOWED_PROVIDERS = frozenset({"ollama", "openai"})


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _messages_safe(messages: list[dict[str, str]]) -> bool:
    if not isinstance(messages, list) or not 1 <= len(messages) <= MAX_HISTORY:
        return False
    return all(
        isinstance(item, dict)
        and item.get("role") in {"user", "assistant"}
        and isinstance(item.get("content"), str)
        and 0 < len(item["content"]) <= MAX_MESSAGE_CHARS
        for item in messages
    )


def _real_chat(provider: str, model: str, messages: list[dict[str, str]]) -> tuple[str, str]:
    timeout = 45.0
    if provider == "ollama":
        base = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434").rstrip("/")
        if not base.startswith(("http://", "https://")):
            raise ValueError("OLLAMA_BASE_URL scheme must be HTTP or HTTPS")
        response = httpx.post(
            base + "/api/chat",
            json={
                "model": model,
                "messages": [{"role": "system", "content": SYSTEM_PROMPT}] + messages,
                "stream": False,
                "options": {"temperature": 0},
            },
            timeout=timeout,
        )
        response.raise_for_status()
        data = response.json()
        output = data.get("message", {}).get("content")
        response_id = data.get("id") or "ollama:" + _digest(canonical_json(data))
    else:
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OpenAI credential not configured")
        endpoint = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/") + "/responses"
        response = httpx.post(
            endpoint,
            headers={"Authorization": "Bearer " + api_key, "Content-Type": "application/json"},
            json={
                "model": model,
                "input": [{"role": "system", "content": SYSTEM_PROMPT}] + messages,
            },
            timeout=timeout,
        )
        response.raise_for_status()
        data = response.json()
        output = data.get("output_text")
        if not output:
            fragments = []
            for item in data.get("output", []):
                for part in item.get("content", []):
                    if part.get("type") in ("output_text", "text") and isinstance(part.get("text"), str):
                        fragments.append(part["text"])
            output = "\n".join(fragments)
        response_id = data.get("id")
    if not isinstance(output, str) or not output.strip():
        raise ValueError("provider returned empty response")
    if not isinstance(response_id, str) or not response_id:
        raise ValueError("provider did not supply response identity")
    return output, response_id


def chat(tenant_id: str, messages: list[dict[str, str]]) -> dict[str, Any]:
    if not _messages_safe(messages):
        return {"status": "BLOCK", "reason": "invalid or excessive chat history"}
    provider = os.getenv("OLA_CHAT_PROVIDER", os.getenv("OLA_LLM_PROVIDER", "ollama")).strip().lower()
    if provider not in ALLOWED_PROVIDERS:
        return {"status": "BLOCK", "reason": "unsupported chat provider"}

    if provider == "ollama":
        model = os.getenv("OLA_CHAT_MODEL", os.getenv("OLA_LLM_MODEL", "qwen2.5:0.5b-instruct")).strip()
    else:
        model = os.getenv("OLA_CHAT_MODEL", os.getenv("NINA_CHAT_MODEL", os.getenv("OLA_LLM_MODEL", "gpt-5.6"))).strip()
    if not model or len(model) > 128:
        return {"status": "BLOCK", "reason": "chat model is not configured"}
    try:
        text, response_id = _real_chat(provider, model, messages)
    except (httpx.HTTPError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        # No network exception text: it may include provider credentials or request details.
        return {"status": "BLOCK", "reason": "configured chat provider unavailable or response invalid"}

    # Writes only a digest and provider identity, never user prompts/response bodies/secrets.
    from .main import append_record

    record = append_record(
        tenant_id,
        "chat.completed",
        {
            "provider": provider,
            "model": model,
            "response_id": response_id,
            "message_count": len(messages),
            "response_digest": _digest(text),
            "scope": "CHAT_ONLY",
        },
    )
    return {
        "status": "VERIFIED",
        "scope": "CHAT_ONLY",
        "message": text,
        "provider": provider,
        "model": model,
        "evidence_id": record["id"],
        "response_digest": _digest(text),
    }
