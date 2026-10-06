import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fake_ollama import FakeOllama  # noqa: E402
from ola_pipeline.config import PipelineConfig, Policy, ProviderConfig  # noqa: E402


@pytest.fixture
def fake():
    f = FakeOllama().start()
    f.add_model("nina-test", digest="a1b2c3d4" * 8)    # a different model has a different digest: equal digests
    f.add_model("igor-test")                           # would mean the same weights (see verify.same_model)
    yield f
    f.stop()


@pytest.fixture
def make_cfg(tmp_path, fake):
    def _make(*, nina_model="nina-test", igor_model="igor-test", policy=None, igor_timeout=10.0,
              nina_provider="ollama-local", igor_provider="ollama-local", nina_url=None):
        return PipelineConfig(
            nina=ProviderConfig(nina_provider, nina_model, base_url=nina_url or fake.url, timeout_s=10.0),
            igor=ProviderConfig(igor_provider, igor_model, base_url=fake.url, timeout_s=igor_timeout,
                                temperature=0.0),
            policy=policy or Policy(allow_test_double=True),
            vault_root=tmp_path / "vault",
        )
    return _make
