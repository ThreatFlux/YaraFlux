"""YaraFlux MCP Server package."""

__version__ = "0.1.0"

# Import the FastAPI app for ASGI servers to find it
try:
    from yaraflux_mcp_server.app import app
except ImportError:
    # This allows the package to be imported even if FastAPI is not installed
    pass
