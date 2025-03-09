"""Wrapper generator utilities for YaraFlux MCP Server.

This module provides utilities for generating MCP tool wrapper functions
to reduce code duplication and implement consistent parameter parsing
and error handling.
"""

import inspect
import logging
from typing import Any, Callable, Dict, Optional, Type, get_type_hints

from mcp.server.fastmcp import FastMCP

from yaraflux_mcp_server.utils.error_handling import handle_tool_error
from yaraflux_mcp_server.utils.param_parsing import extract_typed_params, parse_params

# Configure logging
logger = logging.getLogger(__name__)


def create_tool_wrapper(
    mcp: FastMCP,
    func_name: str,
    actual_func: Callable,
    log_params: bool = True,
) -> Callable:
    """Create an MCP tool wrapper function for an implementation function.

    Args:
        mcp: FastMCP instance to register the tool with
        func_name: Name to register the tool as
        actual_func: The implementation function to wrap
        log_params: Whether to log parameter values (default: True)

    Returns:
        Registered wrapper function
    """
    # Get function signature and type hints
    sig = inspect.signature(actual_func)
    type_hints = get_type_hints(actual_func)

    # Extract parameter metadata
    param_types = {}
    param_defaults = {}

    for param_name, param in sig.parameters.items():
        # Skip 'self' parameter
        if param_name == "self":
            continue

        # Get parameter type
        param_type = type_hints.get(param_name, str)
        param_types[param_name] = param_type

        # Get default value if any
        if param.default is not inspect.Parameter.empty:
            param_defaults[param_name] = param.default

    # Create the wrapper function
    @mcp.tool(name=func_name)
    def wrapper(params: str = "") -> Dict[str, Any]:
        """MCP tool wrapper function.

        Args:
            params: URL-encoded parameter string

        Returns:
            Tool result or error response
        """
        try:
            # Log the call
            if log_params:
                logger.info(f"{func_name} called with params: {params}")
            else:
                logger.info(f"{func_name} called")

            # Parse parameters
            params_dict = parse_params(params)

            # Extract typed parameters
            extracted_params = extract_typed_params(params_dict, param_types, param_defaults)

            # Validate required parameters
            for param_name, param in sig.parameters.items():
                if param_name != "self" and param.default is inspect.Parameter.empty:
                    if param_name not in extracted_params:
                        raise ValueError(f"Required parameter '{param_name}' is missing")

            # Call the actual implementation
            result = actual_func(**extracted_params)

            # Return the result
            return result
        except Exception as e:
            # Handle error
            return handle_tool_error(func_name, e)

    # Return the wrapper function
    return wrapper


def extract_param_schema_from_func(func: Callable) -> Dict[str, Dict[str, Any]]:
    """Extract parameter schema from function signature and docstring.

    Args:
        func: Function to extract schema from

    Returns:
        Parameter schema dictionary
    """
    # Get function signature and type hints
    sig = inspect.signature(func)
    type_hints = get_type_hints(func)
    docstring = inspect.getdoc(func) or ""

    # Create schema
    schema = {}

    # Process each parameter
    for param_name, param in sig.parameters.items():
        if param_name == "self":
            continue

        # Create parameter schema
        param_schema = {
            "required": param.default is inspect.Parameter.empty,
            "type": type_hints.get(param_name, str),
        }

        # Add default value if present
        if param.default is not inspect.Parameter.empty:
            param_schema["default"] = param.default

        # Extract parameter description from docstring
        import re

        param_desc_match = re.search(rf"{param_name}:\s*(.*?)(?:\n\s*\S+:|$)", docstring, re.DOTALL)
        if param_desc_match:
            param_schema["description"] = param_desc_match.group(1).strip()

        # Add to schema
        schema[param_name] = param_schema

    return schema


def register_tool_with_schema(
    mcp: FastMCP,
    func_name: str,
    actual_func: Callable,
    param_schema: Optional[Dict[str, Dict[str, Any]]] = None,
    log_params: bool = True,
) -> Callable:
    """Register a tool with MCP using a parameter schema.

    Args:
        mcp: FastMCP instance to register the tool with
        func_name: Name to register the tool as
        actual_func: The implementation function to call
        param_schema: Optional parameter schema (extracted from function if not provided)
        log_params: Whether to log parameter values

    Returns:
        Registered wrapper function
    """
    # Extract schema from function if not provided
    if param_schema is None:
        param_schema = extract_param_schema_from_func(actual_func)

    # Create wrapper function
    @mcp.tool(name=func_name)
    def wrapper(params: str = "") -> Dict[str, Any]:
        """MCP tool wrapper function.

        Args:
            params: URL-encoded parameter string

        Returns:
            Tool result or error response
        """
        try:
            # Log the call
            if log_params:
                logger.info(f"{func_name} called with params: {params}")
            else:
                logger.info(f"{func_name} called")

            # Parse and validate parameters using schema
            from yaraflux_mcp_server.utils.param_parsing import parse_and_validate_params

            parsed_params = parse_and_validate_params(params, param_schema)

            # Call the actual implementation
            result = actual_func(**parsed_params)

            # Return the result
            return result
        except Exception as e:
            # Handle error
            return handle_tool_error(func_name, e)

    # Return the wrapper function
    return wrapper
