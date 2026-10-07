"""Exception taxonomy. Every operational failure maps to a fail-closed status."""


class OlaPipelineError(Exception):
    pass


class ConfigError(OlaPipelineError):
    pass


class UnknownProviderError(OlaPipelineError):
    pass


class ProviderUnavailable(OlaPipelineError):
    pass


class ModelUnresolved(OlaPipelineError):
    pass


class ProviderTimeout(OlaPipelineError):
    pass


class ProviderError(OlaPipelineError):
    pass


class SecretDetected(OlaPipelineError):
    pass


class ReplayDetected(OlaPipelineError):
    pass


class VaultError(OlaPipelineError):
    pass


class SigningError(OlaPipelineError):
    """Signing was requested but could not be completed. `.run` (when set) holds the unsigned PipelineRun."""

    run = None
