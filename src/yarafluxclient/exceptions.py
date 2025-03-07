"""Exceptions for the YaraFlux MCP Client."""


class YaraFluxClientError(Exception):
    """Base exception for YaraFlux client errors."""


class AuthenticationError(YaraFluxClientError):
    """Authentication error occurred."""


class ValidationError(YaraFluxClientError):
    """Validation error occurred."""


class ConnectionError(YaraFluxClientError):
    """Connection error occurred."""


class ServerError(YaraFluxClientError):
    """Server error occurred."""


class ResourceNotFoundError(YaraFluxClientError):
    """Resource not found error occurred."""
