"""OLA Decision Fabric: typed, fail-closed decision layer for OLA."""
from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from typing import Any, Mapping, Protocol

import httpx

JEV_ENDPOINT = "https://api.typesafe.ai/v1/systemone"
DEFAULT_JEV_MODEL = "jev-1.13.0"
TRANSIENT_STATUS_CODES = {408, 429, 500, 502, 503, 504, 529}


class DecisionProvider(Protocol):
    name: str
    def evaluate(self, *, state: Any, questions: Mapping[str, Mapping[str, Any]], model: str) -> Mapping[str, Any]: ...


@dataclass(frozen=True)
class DecisionResult:
    provider: str
    model: str
    answers: dict[str, Any]
    request_sha256: str
    response_sha256: str
    request_id: str | None
    usage: dict[str, int] | None
    status: str
    reason: str = ""


@dataclass(frozen=True)
class DecisionPolicy:
    min_choice_confidence: float = 0.70
    min_score_confidence: float = 0.70
    noul_yes_threshold: float = 0.80
    noul_no_threshold: float = 0.20

    def classify(self, answer: Mapping[str, Any]) -> str:
        kind = answer.get("type")
        if kind in {"choice", "score"}:
            confidence = float(answer.get("confidence", 0.0))
            threshold = self.min_choice_confidence if kind == "choice" else self.min_score_confidence
            return "ACCEPT" if confidence >= threshold else "REVIEW"
        if kind == "noul":
            value = float(answer.get("noul", 0.5))
            if value >= self.noul_yes_threshold: return "YES"
            if value <= self.noul_no_threshold: return "NO"
            return "REVIEW"
        return "BLOCK"


class JevProvider:
    name = "typesafe-jev"

    def __init__(self, *, api_key: str | None = None, timeout: float = 10.0, max_retries: int = 2,
                 endpoint: str = JEV_ENDPOINT, client: httpx.Client | None = None) -> None:
        self.api_key = api_key or os.getenv("TYPESAFE_API_KEY")
        self.timeout, self.max_retries, self.endpoint, self._client = timeout, max_retries, endpoint, client

    def evaluate(self, *, state: Any, questions: Mapping[str, Mapping[str, Any]], model: str) -> Mapping[str, Any]:
        if not self.api_key:
            raise RuntimeError("TYPESAFE_API_KEY is not configured")
        payload = {"model": model, "state": state, "questions": dict(questions)}
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        owns_client = self._client is None
        client = self._client or httpx.Client(timeout=self.timeout)
        try:
            for attempt in range(self.max_retries + 1):
                try:
                    response = client.post(self.endpoint, json=payload, headers=headers)
                    if response.status_code in TRANSIENT_STATUS_CODES and attempt < self.max_retries:
                        time.sleep(2 ** attempt)
                        continue
                    response.raise_for_status()
                    body = response.json()
                    if not isinstance(body, Mapping):
                        raise ValueError("Jev response body must be an object")
                    return {"body": dict(body), "request_id": response.headers.get("x-request-id")}
                except httpx.HTTPStatusError as exc:
                    if exc.response.status_code not in TRANSIENT_STATUS_CODES or attempt >= self.max_retries:
                        raise
                    time.sleep(2 ** attempt)
                except httpx.RequestError:
                    if attempt >= self.max_retries:
                        raise
                    time.sleep(2 ** attempt)
            raise RuntimeError("Jev request failed")
        finally:
            if owns_client: client.close()


class DecisionFabric:
    def __init__(self, provider: DecisionProvider | None = None, *, model: str = DEFAULT_JEV_MODEL,
                 policy: DecisionPolicy | None = None) -> None:
        self.provider, self.model, self.policy = provider or JevProvider(), model, policy or DecisionPolicy()

    @staticmethod
    def _sha(value: Any) -> str:
        canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @staticmethod
    def _validate_questions(questions: Mapping[str, Mapping[str, Any]], state: Any) -> None:
        if state is None or not isinstance(state, (str, Mapping, list)):
            raise ValueError("state must be a string, object, or array")
        if not questions:
            raise ValueError("at least one question is required")
        for name, q in questions.items():
            if not isinstance(name, str) or not name:
                raise ValueError("question names must be non-empty strings")
            if not isinstance(q, Mapping):
                raise ValueError(f"question {name!r} must be an object")
            kind = q.get("type")
            if kind not in {"choice", "score", "noul"}:
                raise ValueError(f"question {name!r} has unsupported type")
            instructions = q.get("instructions")
            criteria = q.get("criteria")
            if instructions is not None and not isinstance(instructions, (str, Mapping, list)):
                raise ValueError(f"question {name!r} has invalid instructions")
            if kind == "choice":
                if not isinstance(criteria, Mapping) or not 1 <= len(criteria) <= 255:
                    raise ValueError(f"choice question {name!r} requires 1-255 criteria")
            elif kind == "score":
                if not isinstance(criteria, (list, tuple)) or not 2 <= len(criteria) <= 10:
                    raise ValueError(f"score question {name!r} requires 2-10 ordered criteria")
                if any(item is None for item in criteria):
                    raise ValueError(f"score question {name!r} cannot contain null criteria")
            else:
                has_instruction = isinstance(instructions, (str, Mapping, list)) and (
                    not isinstance(instructions, str) or bool(instructions.strip())
                )
                has_noul_criteria = isinstance(criteria, Mapping) and any(
                    key in criteria and criteria[key] is not None for key in ("true", "false")
                )
                if not has_instruction and not has_noul_criteria:
                    raise ValueError(f"noul question {name!r} requires instructions or true/false criteria")

    @staticmethod
    def _validate_answers(questions: Mapping[str, Mapping[str, Any]], answers: Mapping[str, Any]) -> None:
        if set(answers) != set(questions): raise ValueError("provider answer set does not match requested questions")
        for name, q in questions.items():
            a = answers[name]
            if not isinstance(a, Mapping) or a.get("type") != q["type"]:
                raise ValueError(f"answer {name!r} does not match question type")
            kind = q["type"]
            if kind == "choice":
                if a.get("choice") not in q["criteria"]: raise ValueError(f"choice answer {name!r} is outside criteria")
                if not isinstance(a.get("confidence"), (int, float)) or not 0 <= float(a["confidence"]) <= 1:
                    raise ValueError(f"choice answer {name!r} has invalid confidence")
                p = a.get("probabilities")
                if not isinstance(p, Mapping) or set(p) != set(q["criteria"]): raise ValueError(f"choice answer {name!r} has invalid probabilities")
            elif kind == "score":
                if not isinstance(a.get("score"), (int, float)): raise ValueError(f"score answer {name!r} is malformed")
                if not isinstance(a.get("confidence"), (int, float)) or not 0 <= float(a["confidence"]) <= 1:
                    raise ValueError(f"score answer {name!r} has invalid confidence")
                max_score = len(q["criteria"]) - 1
                if not 0 <= float(a["score"]) <= max_score:
                    raise ValueError(f"score answer {name!r} is outside rubric range")
                probabilities = a.get("probabilities")
                if not isinstance(probabilities, Mapping):
                    raise ValueError(f"score answer {name!r} has invalid probabilities")
                expected_keys = {str(i) for i in range(len(q["criteria"]))}
                if set(probabilities) != expected_keys:
                    raise ValueError(f"score answer {name!r} has invalid probability keys")
                if any(not isinstance(value, (int, float)) or not 0 <= float(value) <= 1 for value in probabilities.values()):
                    raise ValueError(f"score answer {name!r} has invalid probability values")
                legend = a.get("legend")
                if not isinstance(legend, Mapping) or set(legend) != expected_keys:
                    raise ValueError(f"score answer {name!r} has invalid legend")
            elif not isinstance(a.get("noul"), (int, float)) or not 0 <= float(a["noul"]) <= 1:
                raise ValueError(f"noul answer {name!r} is malformed")

    def evaluate(self, *, state: Any, questions: Mapping[str, Mapping[str, Any]]) -> DecisionResult:
        request = {"model": self.model, "state": state, "questions": dict(questions)}
        request_sha = self._sha(request)
        try:
            self._validate_questions(questions, state)
            raw = self.provider.evaluate(state=state, questions=questions, model=self.model)
            if not isinstance(raw, Mapping): raise ValueError("provider result must be an object")
            body = raw.get("body", raw)
            if not isinstance(body, Mapping): raise ValueError("provider body must be an object")
            answers = body.get("answers")
            if not isinstance(answers, Mapping): raise ValueError("provider answers must be an object")
            answers = dict(answers)
            self._validate_answers(questions, answers)
            usage = body.get("usage")
            usage_out = None
            if isinstance(usage, Mapping) and isinstance(usage.get("input_tokens"), int) and isinstance(usage.get("output_tokens"), int):
                usage_out = {"input_tokens": usage["input_tokens"], "output_tokens": usage["output_tokens"]}
            return DecisionResult(self.provider.name, str(body.get("model", self.model)), answers, request_sha,
                                  self._sha(body), raw.get("request_id"), usage_out, "READY")
        except Exception as exc:
            return DecisionResult(self.provider.name, self.model, {}, request_sha,
                                  self._sha({"error": exc.__class__.__name__}), None, None, "BLOCK",
                                  f"decision contract/provider failure: {exc.__class__.__name__}")

    def classify(self, result: DecisionResult) -> dict[str, str]:
        if result.status != "READY": return {}
        return {name: self.policy.classify(answer) for name, answer in result.answers.items()}

    def evidence(self, result: DecisionResult) -> dict[str, Any]:
        return {"schema": "ola.decision.v1", "provider": result.provider, "model": result.model,
                "status": result.status, "reason": result.reason, "request_sha256": result.request_sha256,
                "response_sha256": result.response_sha256, "request_id": result.request_id, "usage": result.usage,
                "answers": result.answers, "classifications": self.classify(result)}
