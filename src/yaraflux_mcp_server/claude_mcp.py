"""
Simplified MCP implementation for Claude Desktop integration.

This module provides a minimal implementation of the Model Context Protocol
that works reliably with Claude Desktop, avoiding dependency on external MCP packages.
"""

import inspect
import json
import logging
from typing import Any, Callable, Dict, List, Optional, Type, get_args, get_origin, get_type_hints

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Store registered tools
_REGISTERED_TOOLS = {}


def register_tool(func: Callable) -> Callable:
    """Register a function as an MCP tool.

    This decorator registers the function to be exposed as an MCP tool
    to Claude Desktop, automatically generating the name and schema
    from the function signature.

    Args:
        func: The function to register as a tool

    Returns:
        The original function unchanged
    """
    try:
        # Extract function metadata
        name = func.__name__
        doc = func.__doc__ or "No description available"
        description = doc.split("\n\n")[0].strip() if doc else "No description available"

        # Get type hints and signature
        hints = get_type_hints(func)
        sig = inspect.signature(func)

        # Create schema properties
        properties = {}
        required = []

        # Process each parameter
        for param_name, param in sig.parameters.items():
            if param_name == "self":
                continue

            # Set as required if no default value
            if param.default is inspect.Parameter.empty:
                required.append(param_name)

            # Get parameter type
            param_type = hints.get(param_name, Any)
            schema_type = "string"  # Default type

            # Map Python types to JSON Schema types
            if param_type is str:
                schema_type = "string"
            elif param_type is int:
                schema_type = "integer"
            elif param_type is float:
                schema_type = "number"
            elif param_type is bool:
                schema_type = "boolean"
            elif get_origin(param_type) is list or get_origin(param_type) is List:
                schema_type = "array"
            elif get_origin(param_type) is dict or get_origin(param_type) is Dict:
                schema_type = "object"
            elif param_type is Any:
                schema_type = "string"

            # Create parameter property
            properties[param_name] = {"type": schema_type}

            # Extract parameter description from docstring
            if doc:
                param_doc = None
                for line in doc.split("\n"):
                    if line.strip().startswith(f"{param_name}:"):
                        param_doc = line.split(":", 1)[1].strip()
                        break

                if param_doc:
                    properties[param_name]["description"] = param_doc

        # Create input schema
        input_schema = {"type": "object", "properties": properties, "required": required}

        # Register the tool
        _REGISTERED_TOOLS[name] = {
            "name": name,
            "description": description,
            "function": func,
            "input_schema": input_schema,
        }

        logger.info(f"Registered MCP tool: {name}")
        return func

    except Exception as e:
        logger.error(f"Error registering MCP tool {func.__name__}: {str(e)}")
        return func


def get_all_tools() -> List[Dict[str, Any]]:
    """Get all registered tools as a list of schema objects."""
    result = []
    for name, tool in _REGISTERED_TOOLS.items():
        result.append(
            {
                "name": tool["name"],
                "description": tool["description"],
                "inputSchema": tool["input_schema"],
            }
        )
    return result


def execute_tool(name: str, params: Dict[str, Any]) -> Any:
    """Execute a registered tool with the given parameters."""
    if name not in _REGISTERED_TOOLS:
        raise ValueError(f"Tool not found: {name}")

    tool = _REGISTERED_TOOLS[name]
    function = tool["function"]

    try:
        result = function(**params)
        return result
    except Exception as e:
        logger.error(f"Error executing tool {name}: {str(e)}")
        raise


def init_fastapi(app):
    """Initialize FastAPI routes for MCP."""
    from fastapi import HTTPException, Request

    @app.get("/mcp/v1/tools")
    async def get_tools():
        """Return all registered tools."""
        return get_all_tools()

    @app.post("/mcp/v1/execute")
    async def execute(request: Request):
        """Execute a tool with parameters."""
        try:
            data = await request.json()
            name = data.get("name")
            params = data.get("parameters", {})

            if not name:
                raise HTTPException(status_code=400, detail="Tool name is required")

            result = execute_tool(name, params)
            return {"result": result}
        except Exception as e:
            logger.error(f"Error in execute endpoint: {str(e)}")
            raise HTTPException(status_code=500, detail=str(e))

    logger.info("Initialized MCP FastAPI routes")
    return app
