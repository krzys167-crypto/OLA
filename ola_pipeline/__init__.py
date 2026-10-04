"""OLA DI-OS evidence-driven pipeline: NINA -> OLLAMA -> EVIDENCE -> IGOR -> GATE -> REPLAY."""
from .config import PipelineConfig, Policy, ProviderConfig
from .pipeline import Pipeline, PipelineRun
from .verify import verify_session

__all__ = ["Pipeline", "PipelineRun", "PipelineConfig", "Policy", "ProviderConfig", "verify_session"]
__version__ = "0.1.0"
