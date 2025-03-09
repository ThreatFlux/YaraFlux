"""Parameter parsing utilities for YaraFlux MCP Server.

This module provides utility functions for parsing parameters from
string format into Python data types, with support for validation
against parameter schemas.
"""

import json
import logging
import urllib.parse
from typing import Any, Dict, List, Optional, Type, Union, get_args, get_origin

# Configure logging
logger = logging.getLogger(__name__)


def parse_params(params_str: str) -> Dict[str, Any]:
    """Parse a URL-encoded string into a dictionary of parameters.

    Args:
        params_str: String containing URL-encoded parameters

    Returns:
        Dictionary of parsed parameters

    Raises:
        ValueError: If the string cannot be parsed
    """
    if not params_str:
        return {}

    # Handle both simple key=value format and URL-encoded format
    try:
        # Try URL-encoded format
        params_dict = {}
        pairs = params_str.split("&")
        for pair in pairs:
            if "=" in pair:
                key, value = pair.split("=", 1)
                params_dict[key] = urllib.parse.unquote(value)
            else:
                params_dict[pair] = ""
        return params_dict
    except Exception as e:
        logger.error(f"Error parsing params string: {str(e)}")
        raise ValueError(f"Failed to parse parameters: {str(e)}")


def convert_param_type(value: str, param_type: Type) -> Any:
    """Convert a string parameter to the specified Python type.

    Args:
        value: String value to convert
        param_type: Target Python type

    Returns:
        Converted value

    Raises:
        ValueError: If the value cannot be converted to the specified type
    """
    origin = get_origin(param_type)
    args = get_args(param_type)

    # Handle Optional types
    if origin is Union and type(None) in args:
        # If it's Optional[X], extract X
        for arg in args:
            if arg is not type(None):
                param_type = arg
                break
        # If value is empty and type is optional, return None
        if not value:
            return None

    try:
        # Handle basic types
        if param_type is str:
            return value
        elif param_type is int:
            return int(value)
        elif param_type is float:
            return float(value)
        elif param_type is bool:
            # Handle both string and boolean inputs
            if isinstance(value, bool):
                return value
            elif isinstance(value, str):
                return value.lower() in ("true", "yes", "1", "t", "y")
            elif isinstance(value, int):
                return bool(value)
            else:
                return bool(value)  # Try to convert any other type
        # Handle list types
        elif origin is list or origin is List:
            if not value:
                return []
            # For lists, split by comma if it's a string
            if isinstance(value, str):
                items = value.split(",")
                # If we have type args, convert each item
                if args and args[0] is not Any:
                    item_type = args[0]
                    return [convert_param_type(item.strip(), item_type) for item in items]
                return [item.strip() for item in items]
            return value
        # Handle dict types
        elif origin is dict or origin is Dict:
            if isinstance(value, str):
                try:
                    return json.loads(value)
                except json.JSONDecodeError:
                    # If not valid JSON, just return a dict with the string
                    return {"value": value}
            return value
        # For any other type, just return the value
        return value
    except Exception as e:
        logger.error(f"Error converting parameter to {param_type}: {str(e)}")
        raise ValueError(f"Failed to convert parameter to {param_type}: {str(e)}")


def extract_typed_params(
    params_dict: Dict[str, str], 
    param_types: Dict[str, Type], 
    param_defaults: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Extract and type-convert parameters from a dictionary based on type hints.
    
    Args:
        params_dict: Dictionary of string parameters
        param_types: Dictionary mapping parameter names to their types
        param_defaults: Optional dictionary of default values
        
    Returns:
        Dictionary of typed parameters
        
    Raises:
        ValueError: If a required parameter is missing or cannot be converted
    """
    result: Dict[str, Any] = {}
    
    defaults: Dict[str, Any] = {} if param_defaults is None else param_defaults

    for name, param_type in param_types.items():
        # Get parameter value (use default if not provided)
        value = params_dict.get(name, param_defaults.get(name, None))

        # Skip None values
        if value is None:
            continue

        # Convert value to the right type
        result[name] = convert_param_type(value, param_type)

    return result


def parse_and_validate_params(params_str: str, param_schema: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Parse a URL-encoded string and validate against a parameter schema.

    Args:
        params_str: String containing URL-encoded parameters
        param_schema: Schema defining parameter types and requirements

    Returns:
        Dictionary of validated parameters

    Raises:
        ValueError: If validation fails or a required parameter is missing
    """
    # Parse parameters
    params_dict = parse_params(params_str)
    result = {}

    # Extract parameter types and defaults
    param_types = {}
    param_defaults = {}

    for name, schema in param_schema.items():
        param_type = schema.get("type", str)
        param_types[name] = param_type

        if "default" in schema:
            param_defaults[name] = schema["default"]

    # Convert parameters to their types
    typed_params = extract_typed_params(params_dict, param_types, param_defaults)

    # Validate required parameters
    for name, schema in param_schema.items():
        if schema.get("required", False) and name not in typed_params:
            raise ValueError(f"Required parameter '{name}' is missing")

        # Add to result
        if name in typed_params:
            result[name] = typed_params[name]
        elif name in param_defaults:
            result[name] = param_defaults[name]

    return result
