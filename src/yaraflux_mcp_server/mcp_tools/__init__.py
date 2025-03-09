"""Claude MCP Tools package.

This package provides MCP tools for integration with Claude Desktop and FastAPI.
It exposes all tools through a unified interface while maintaining compatibility
with both Claude Desktop and the FastAPI application.
"""

import importlib
import logging
from typing import Any, Dict, List

from fastapi import FastAPI, HTTPException, Request

from .base import ToolRegistry, register_tool

# Configure logging
logger = logging.getLogger(__name__)


def init_fastapi(app: FastAPI) -> FastAPI:
    """Initialize FastAPI with MCP endpoints.

    This function sets up the necessary endpoints for MCP tool discovery
    and execution in the FastAPI application.

    Args:
        app: FastAPI application instance

    Returns:
        Configured FastAPI application
    """

    @app.get("/mcp/v1/tools")
    async def get_tools() -> List[Dict[str, Any]]:
        """Get all registered MCP tools.

        Returns:
            List of tool metadata objects
        """
        try:
            return ToolRegistry.get_all_tools()
        except Exception as e:
            logger.error(f"Error getting tools: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Error getting tools: {str(e)}")

    @app.post("/mcp/v1/execute")
    async def execute_tool(request: Request) -> Dict[str, Any]:
        """Execute an MCP tool.

        Args:
            request: FastAPI request object

        Returns:
            Tool execution result

        Raises:
            HTTPException: If tool execution fails
        """
        try:
            data = await request.json()
            name = data.get("name")
            params = data.get("parameters", {})

            if not name:
                raise HTTPException(status_code=400, detail="Tool name is required")

            result = ToolRegistry.execute_tool(name, params)
            return {"result": result}
        except KeyError as e:
            raise HTTPException(status_code=404, detail=str(e))
        except Exception as e:
            logger.error(f"Error executing tool: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Error executing tool: {str(e)}")


# Import tool modules dynamically to prevent circular imports
def _import_module(module_name):
    try:
        return importlib.import_module(f".{module_name}", package="yaraflux_mcp_server.mcp_tools")
    except ImportError as e:
        logger.warning(f"Could not import {module_name}: {str(e)}")
        return None


# Load all tool modules
_import_module("file_tools")
_import_module("scan_tools")
_import_module("rule_tools")
_import_module("storage_tools")

# Export public interface
__all__ = ["register_tool", "init_fastapi", "ToolRegistry"]
