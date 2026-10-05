"""Configuration. No model name is hardcoded: it must come from env/config."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

from .errors import ConfigError

DEFAULT_BASE_URLS = {
    "ollama-local": "http://localhost:11434",
    "ollama-cloud": "https://ollama.com",
    "openai": "https://api.openai.com",
}
DEFAULT_KEY_ENV = {"ollama-cloud": "OLLAMA_API_KEY", "openai": "OPENAI_API_KEY"}

DEFAULT_REQUIREMENTS: Tuple[str, ...] = (
    "Answers the task completely and directly.",
    "Contains no fabricated facts; states uncertainty or missing information explicitly.",
    "Is internally consistent and free of contradictions.",
    "Follows every explicit constraint stated in the task.",
)


@dataclass(frozen=True)
class ProviderConfig:
    provider: str
    model: str
    base_url: str = ""
    api_key_env: str = ""
    timeout_s: float = 180.0
    temperature: float = 0.2
    seed: Optional[int] = None
    max_tokens: Optional[int] = None
    think: Optional[bool] = None  # None = do not send; True/False = Ollama `think` (reasoning models)

    def effective_base_url(self) -> str:
        return (self.base_url or DEFAULT_BASE_URLS.get(self.provider, "")).rstrip("/")

    def effective_key_env(self) -> str:
        return self.api_key_env or DEFAULT_KEY_ENV.get(self.provider, "")

    def known_secrets(self) -> Tuple[str, ...]:
        name = self.effective_key_env()
        val = os.environ.get(name, "") if name else ""
        return (val,) if val else ()

    def public_endpoint(self) -> str:
        """Endpoint without userinfo/query/fragment — safe to persist."""
        u = urlsplit(self.effective_base_url())
        host = u.hostname or ""
        if u.port:
            host = f"{host}:{u.port}"
        return urlunsplit((u.scheme, host, u.path, "", ""))


@dataclass(frozen=True)
class Policy:
    max_iterations: int = 3
    min_quality_score: int = 70
    require_model_digest: bool = True
    # TEST ONLY: lets a declared test double through the Gate. Evidence is then
    # labelled TEST_DOUBLE and the verifier never reports VERIFIED for it.
    allow_test_double: bool = False
    # PASS from a judge that cannot be shown to reject a known-wrong answer is not verification.
    require_igor_calibration: bool = True
    # Same provider+model grading its own output is self-verification; forbidden unless opted in.
    allow_same_model_igor: bool = False

    def validate(self) -> "Policy":
        if not 1 <= self.max_iterations <= 3:
            raise ConfigError("max_iterations must be within 1..3")
        if not 0 <= self.min_quality_score <= 100:
            raise ConfigError("min_quality_score must be within 0..100")
        return self


@dataclass(frozen=True)
class PipelineConfig:
    nina: ProviderConfig
    igor: ProviderConfig
    policy: Policy = Policy()
    vault_root: Path = Path("./ola_evidence")
    quality_requirements: Tuple[str, ...] = DEFAULT_REQUIREMENTS
    # Path to an Ed25519 seed file kept OUTSIDE the vault. None = sessions are not signed.
    signing_key_file: Optional[Path] = None

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "PipelineConfig":
        env = os.environ if env is None else env

        def f(name: str, default: str) -> float:
            try:
                return float(env.get(name, default))
            except ValueError:
                raise ConfigError(f"{name} is not a number") from None

        def i(name: str) -> Optional[int]:
            raw = env.get(name, "")
            if raw == "":
                return None
            try:
                return int(raw)
            except ValueError:
                raise ConfigError(f"{name} is not an integer") from None

        def b(name: str) -> Optional[bool]:
            raw = env.get(name, "")
            if raw == "":
                return None
            if raw not in ("0", "1"):
                raise ConfigError(f"{name} must be 0 or 1")
            return raw == "1"

        provider = env.get("OLA_NINA_PROVIDER", "ollama-local")
        nina = ProviderConfig(
            provider=provider,
            model=env.get("OLA_NINA_MODEL", ""),
            base_url=env.get("OLA_NINA_BASE_URL", ""),
            api_key_env=env.get("OLA_NINA_API_KEY_ENV", ""),
            timeout_s=f("OLA_NINA_TIMEOUT_S", "180"),
            temperature=f("OLA_NINA_TEMPERATURE", "0.2"),
            seed=i("OLA_NINA_SEED"),
            max_tokens=i("OLA_NINA_MAX_TOKENS"),
            think=b("OLA_NINA_THINK"),
        )
        igor = ProviderConfig(
            provider=env.get("OLA_IGOR_PROVIDER", provider),
            model=env.get("OLA_IGOR_MODEL", nina.model),
            base_url=env.get("OLA_IGOR_BASE_URL", nina.base_url),
            api_key_env=env.get("OLA_IGOR_API_KEY_ENV", nina.api_key_env),
            timeout_s=f("OLA_IGOR_TIMEOUT_S", "180"),
            temperature=f("OLA_IGOR_TEMPERATURE", "0.0"),
            seed=i("OLA_IGOR_SEED"),
            max_tokens=i("OLA_IGOR_MAX_TOKENS"),
            think=b("OLA_IGOR_THINK"),
        )
        policy = Policy(
            max_iterations=3 if i("OLA_MAX_ITERATIONS") is None else i("OLA_MAX_ITERATIONS"),
            min_quality_score=70 if i("OLA_MIN_QUALITY_SCORE") is None else i("OLA_MIN_QUALITY_SCORE"),
            require_model_digest=env.get("OLA_REQUIRE_MODEL_DIGEST", "1") != "0",
            require_igor_calibration=env.get("OLA_REQUIRE_IGOR_CALIBRATION", "1") != "0",
            allow_same_model_igor=env.get("OLA_ALLOW_SAME_MODEL_IGOR", "0") == "1",
        ).validate()
        reqs = tuple(
            x.strip() for x in env.get("OLA_QUALITY_REQUIREMENTS", "").split("\n") if x.strip()
        ) or DEFAULT_REQUIREMENTS
        key = env.get("OLA_SIGNING_KEY_FILE", "")
        return cls(nina, igor, policy, Path(env.get("OLA_VAULT_DIR", "./ola_evidence")), reqs,
                   signing_key_file=Path(key) if key else None)
