"""YaraFlux MCP Client package.

This package provides a client for interacting with the YaraFlux MCP Server.
"""

from yarafluxclient.client import YaraFluxClient
from yarafluxclient.exceptions import YaraFluxClientError

__version__ = "0.1.0"
__all__ = ["YaraFluxClient", "YaraFluxClientError"]
