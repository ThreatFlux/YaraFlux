"""Storage abstraction for YaraFlux MCP Server (Legacy Module).

This module is maintained for backward compatibility. New code should import directly
from the yaraflux_mcp_server.storage package instead.
"""

# Re-export everything from the new storage package
from yaraflux_mcp_server.storage import (
    LocalStorageClient,
    StorageClient,
    StorageError,
    get_storage_client,
)

# Try to re-export MinioStorageClient if available
try:
    from yaraflux_mcp_server.storage import MinioStorageClient

    __all__ = ["StorageError", "StorageClient", "LocalStorageClient", "MinioStorageClient", "get_storage_client"]
except ImportError:
    __all__ = ["StorageError", "StorageClient", "LocalStorageClient", "get_storage_client"]

# Log deprecation warning
import logging

logger = logging.getLogger(__name__)
logger.warning(
    "Importing from yaraflux_mcp_server.storage module is deprecated. "
    "Please import from yaraflux_mcp_server.storage package instead."
)
