"""YaraFlux MCP Server implementation using the official MCP SDK.

This module creates a proper MCP server that exposes YARA functionality
to Claude Desktop following the Model Context Protocol specification.
This version properly integrates the modular mcp_tools package.
"""

import asyncio
import base64
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from mcp.server.fastmcp import Context, FastMCP

from yaraflux_mcp_server.auth import init_user_db
from yaraflux_mcp_server.config import settings
from yaraflux_mcp_server.storage import get_storage_client
from yaraflux_mcp_server.yara_service import YaraError, yara_service

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Import all tools from the modular mcp_tools package
# This will register them with ToolRegistry
import yaraflux_mcp_server.mcp_tools

# Create an MCP server
mcp = FastMCP(
    "YaraFlux",
    title="YaraFlux YARA Scanning Server",
    description="MCP server for YARA rule management and file scanning",
    version="0.1.0",
)

import importlib
import urllib.parse

# Register all tools from ToolRegistry with FastMCP
from yaraflux_mcp_server.mcp_tools import ToolRegistry
from yaraflux_mcp_server.mcp_tools.file_tools import delete_file as delete_file_func
from yaraflux_mcp_server.mcp_tools.file_tools import download_file as download_file_func
from yaraflux_mcp_server.mcp_tools.file_tools import extract_strings as extract_strings_func
from yaraflux_mcp_server.mcp_tools.file_tools import get_file_info as get_file_info_func
from yaraflux_mcp_server.mcp_tools.file_tools import get_hex_view as get_hex_view_func
from yaraflux_mcp_server.mcp_tools.file_tools import list_files as list_files_func
from yaraflux_mcp_server.mcp_tools.file_tools import upload_file as upload_file_func
from yaraflux_mcp_server.mcp_tools.rule_tools import add_yara_rule as add_yara_rule_func
from yaraflux_mcp_server.mcp_tools.rule_tools import delete_yara_rule as delete_yara_rule_func
from yaraflux_mcp_server.mcp_tools.rule_tools import get_yara_rule as get_yara_rule_func
from yaraflux_mcp_server.mcp_tools.rule_tools import import_threatflux_rules as import_threatflux_rules_func
from yaraflux_mcp_server.mcp_tools.rule_tools import list_yara_rules as list_yara_rules_func
from yaraflux_mcp_server.mcp_tools.rule_tools import update_yara_rule as update_yara_rule_func
from yaraflux_mcp_server.mcp_tools.rule_tools import validate_yara_rule as validate_yara_rule_func

# Get all actual tool functions for later use
from yaraflux_mcp_server.mcp_tools.scan_tools import get_scan_result as get_scan_result_func
from yaraflux_mcp_server.mcp_tools.scan_tools import scan_data as scan_data_func
from yaraflux_mcp_server.mcp_tools.scan_tools import scan_url as scan_url_func
from yaraflux_mcp_server.mcp_tools.storage_tools import clean_storage as clean_storage_func
from yaraflux_mcp_server.mcp_tools.storage_tools import get_storage_info as get_storage_info_func

# Log the tools found in ToolRegistry
logger.info(f"Found {len(ToolRegistry._tools)} tools in ToolRegistry")
for tool_name in ToolRegistry._tools:
    logger.info(f"Registering tool from ToolRegistry: {tool_name}")


# Helper function to parse tool parameters
def parse_params(params_str):
    """Parse a URL-encoded string into a dictionary of parameters."""
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
        return {}


# Register wrappers for each tool with proper params handling
# scan_url
@mcp.tool(name="scan_url")
def scan_url_wrapper(params: str = "") -> Dict[str, Any]:
    """Wrapper for scan_url tool that accepts a params string."""
    try:
        logger.info(f"scan_url called with params: {params}")
        params_dict = parse_params(params)
        url = params_dict.get("url", "")
        rule_names = params_dict.get("rule_names", None)
        if rule_names and isinstance(rule_names, str):
            rule_names = rule_names.split(",")
        sources = params_dict.get("sources", None)
        if sources and isinstance(sources, str):
            sources = sources.split(",")
        timeout = params_dict.get("timeout", None)
        if timeout:
            timeout = int(timeout)

        logger.info(f"Parsed params: url={url}, rule_names={rule_names}, sources={sources}, timeout={timeout}")
        return scan_url_func(url, rule_names, sources, timeout)
    except Exception as e:
        logger.error(f"Error in scan_url_wrapper: {str(e)}")
        return {"success": False, "message": f"Error: {str(e)}"}


# get_hex_view
@mcp.tool(name="get_hex_view")
def get_hex_view_wrapper(params: str = "") -> Dict[str, Any]:
    """Wrapper for get_hex_view tool that accepts a params string."""
    try:
        logger.info(f"get_hex_view called with params: {params}")
        params_dict = parse_params(params)
        file_id = params_dict.get("file_id", "")
        offset = int(params_dict.get("offset", "0"))
        length = params_dict.get("length", None)
        if length:
            length = int(length)
        bytes_per_line = int(params_dict.get("bytes_per_line", "16"))

        logger.info(
            f"Parsed params: file_id={file_id}, offset={offset}, length={length}, bytes_per_line={bytes_per_line}"
        )
        return get_hex_view_func(file_id, offset, length, bytes_per_line)
    except Exception as e:
        logger.error(f"Error in get_hex_view_wrapper: {str(e)}")
        return {"success": False, "message": f"Error getting hex view: {str(e)}"}


# list_yara_rules
@mcp.tool(name="list_yara_rules")
def list_yara_rules_wrapper(params: str = "") -> List[Dict[str, Any]]:
    """Wrapper for list_yara_rules tool that accepts a params string."""
    try:
        logger.info(f"list_yara_rules called with params: {params}")
        params_dict = parse_params(params)
        source = params_dict.get("source", None)

        logger.info(f"Parsed params: source={source}")
        return list_yara_rules_func(source)
    except Exception as e:
        logger.error(f"Error in list_yara_rules_wrapper: {str(e)}")
        return []


# get_yara_rule
@mcp.tool(name="get_yara_rule")
def get_yara_rule_wrapper(params: str = "") -> Dict[str, Any]:
    """Wrapper for get_yara_rule tool that accepts a params string."""
    try:
        logger.info(f"get_yara_rule called with params: {params}")
        params_dict = parse_params(params)
        rule_name = params_dict.get("rule_name", "")
        source = params_dict.get("source", "custom")

        logger.info(f"Parsed params: rule_name={rule_name}, source={source}")
        return get_yara_rule_func(rule_name, source)
    except Exception as e:
        logger.error(f"Error in get_yara_rule_wrapper: {str(e)}")
        return {"name": "", "source": "", "error": str(e)}


# validate_yara_rule
@mcp.tool(name="validate_yara_rule")
def validate_yara_rule_wrapper(params: str = "") -> Dict[str, Any]:
    """Wrapper for validate_yara_rule tool that accepts a params string."""
    try:
        logger.info(f"validate_yara_rule called with params: {params}")
        params_dict = parse_params(params)
        content = params_dict.get("content", "")

        logger.info(f"Parsed params: content length={len(content)}")
        return validate_yara_rule_func(content)
    except Exception as e:
        logger.error(f"Error in validate_yara_rule_wrapper: {str(e)}")
        return {"valid": False, "message": str(e)}


# add_yara_rule
@mcp.tool(name="add_yara_rule")
def add_yara_rule_wrapper(params: str = "") -> Dict[str, Any]:
    """Wrapper for add_yara_rule tool that accepts a params string."""
    try:
        logger.info(f"add_yara_rule called with params: {params}")
        params_dict = parse_params(params)
        name = params_dict.get("name", "")
        content = params_dict.get("content", "")
        source = params_dict.get("source", "custom")

        logger.info(f"Parsed params: name={name}, source={source}, content length={len(content)}")
        return add_yara_rule_func(name, content, source)
    except Exception as e:
        logger.error(f"Error in add_yara_rule_wrapper: {str(e)}")
        return {"success": False, "message": str(e)}


# upload_file
@mcp.tool(name="upload_file")
def upload_file_wrapper(params: str = "") -> Dict[str, Any]:
    """Wrapper for upload_file tool that accepts a params string."""
    try:
        logger.info(f"upload_file called with params length: {len(params) if params else 0}")
        params_dict = parse_params(params)
        data = params_dict.get("data", "")
        file_name = params_dict.get("file_name", "")
        encoding = params_dict.get("encoding", "base64")
        metadata_str = params_dict.get("metadata", "{}")

        # Parse metadata if provided
        try:
            import json

            metadata = json.loads(metadata_str)
        except Exception:
            metadata = {}

        logger.info(f"Parsed params: file_name={file_name}, encoding={encoding}, data length={len(data)}")
        return upload_file_func(data, file_name, encoding, metadata)
    except Exception as e:
        logger.error(f"Error in upload_file_wrapper: {str(e)}")
        return {"success": False, "message": f"Error uploading file: {str(e)}"}


# get_file_info
@mcp.tool(name="get_file_info")
def get_file_info_wrapper(params: str = "") -> Dict[str, Any]:
    """Wrapper for get_file_info tool that accepts a params string."""
    try:
        logger.info(f"get_file_info called with params: {params}")
        params_dict = parse_params(params)
        file_id = params_dict.get("file_id", "")

        logger.info(f"Parsed params: file_id={file_id}")
        return get_file_info_func(file_id)
    except Exception as e:
        logger.error(f"Error in get_file_info_wrapper: {str(e)}")
        return {"success": False, "message": f"Error getting file info: {str(e)}"}


# list_files
@mcp.tool(name="list_files")
def list_files_wrapper(params: str = "") -> Dict[str, Any]:
    """Wrapper for list_files tool that accepts a params string."""
    try:
        logger.info(f"list_files called with params: {params}")
        params_dict = parse_params(params)
        page = int(params_dict.get("page", "1"))
        page_size = int(params_dict.get("page_size", "100"))
        sort_by = params_dict.get("sort_by", "uploaded_at")
        sort_desc_str = params_dict.get("sort_desc", "true")
        sort_desc = sort_desc_str.lower() == "true"

        logger.info(f"Parsed params: page={page}, page_size={page_size}, sort_by={sort_by}, sort_desc={sort_desc}")
        return list_files_func(page, page_size, sort_by, sort_desc)
    except Exception as e:
        logger.error(f"Error in list_files_wrapper: {str(e)}")
        return {"success": False, "message": f"Error listing files: {str(e)}"}


# delete_file
@mcp.tool(name="delete_file")
def delete_file_wrapper(params: str = "") -> Dict[str, Any]:
    """Wrapper for delete_file tool that accepts a params string."""
    try:
        logger.info(f"delete_file called with params: {params}")
        params_dict = parse_params(params)
        file_id = params_dict.get("file_id", "")

        logger.info(f"Parsed params: file_id={file_id}")
        return delete_file_func(file_id)
    except Exception as e:
        logger.error(f"Error in delete_file_wrapper: {str(e)}")
        return {"success": False, "message": f"Error deleting file: {str(e)}"}


# extract_strings
@mcp.tool(name="extract_strings")
def extract_strings_wrapper(params: str = "") -> Dict[str, Any]:
    """Wrapper for extract_strings tool that accepts a params string."""
    try:
        logger.info(f"extract_strings called with params: {params}")
        params_dict = parse_params(params)
        file_id = params_dict.get("file_id", "")
        min_length = int(params_dict.get("min_length", "4"))
        include_unicode_str = params_dict.get("include_unicode", "true")
        include_unicode = include_unicode_str.lower() == "true"
        include_ascii_str = params_dict.get("include_ascii", "true")
        include_ascii = include_ascii_str.lower() == "true"
        limit_str = params_dict.get("limit", None)
        limit = int(limit_str) if limit_str else None

        logger.info(
            f"Parsed params: file_id={file_id}, min_length={min_length}, include_unicode={include_unicode}, include_ascii={include_ascii}, limit={limit}"
        )
        return extract_strings_func(file_id, min_length, include_unicode, include_ascii, limit)
    except Exception as e:
        logger.error(f"Error in extract_strings_wrapper: {str(e)}")
        return {"success": False, "message": f"Error extracting strings: {str(e)}"}


# download_file
@mcp.tool(name="download_file")
def download_file_wrapper(params: str = "") -> Dict[str, Any]:
    """Wrapper for download_file tool that accepts a params string."""
    try:
        logger.info(f"download_file called with params: {params}")
        params_dict = parse_params(params)
        file_id = params_dict.get("file_id", "")
        encoding = params_dict.get("encoding", "base64")

        logger.info(f"Parsed params: file_id={file_id}, encoding={encoding}")
        return download_file_func(file_id, encoding)
    except Exception as e:
        logger.error(f"Error in download_file_wrapper: {str(e)}")
        return {"success": False, "message": f"Error downloading file: {str(e)}"}


# scan_data
@mcp.tool(name="scan_data")
def scan_data_wrapper(params: str = "") -> Dict[str, Any]:
    """Wrapper for scan_data tool that accepts a params string."""
    try:
        logger.info(f"scan_data called with params length: {len(params) if params else 0}")
        params_dict = parse_params(params)
        data = params_dict.get("data", "")
        filename = params_dict.get("filename", "unknown_file")
        encoding = params_dict.get("encoding", "base64")
        rule_names = params_dict.get("rule_names", None)
        if rule_names and isinstance(rule_names, str):
            rule_names = rule_names.split(",")
        sources = params_dict.get("sources", None)
        if sources and isinstance(sources, str):
            sources = sources.split(",")
        timeout = params_dict.get("timeout", None)
        if timeout:
            timeout = int(timeout)

        logger.info(
            f"Parsed params: filename={filename}, encoding={encoding}, data length={len(data)}, rule_names={rule_names}, sources={sources}, timeout={timeout}"
        )
        return scan_data_func(data, filename, encoding, rule_names, sources, timeout)
    except Exception as e:
        logger.error(f"Error in scan_data_wrapper: {str(e)}")
        return {"success": False, "message": f"Error: {str(e)}"}


# get_scan_result
@mcp.tool(name="get_scan_result")
def get_scan_result_wrapper(params: str = "") -> Dict[str, Any]:
    """Wrapper for get_scan_result tool that accepts a params string."""
    try:
        logger.info(f"get_scan_result called with params: {params}")
        params_dict = parse_params(params)
        scan_id = params_dict.get("scan_id", "")

        logger.info(f"Parsed params: scan_id={scan_id}")
        return get_scan_result_func(scan_id)
    except Exception as e:
        logger.error(f"Error in get_scan_result_wrapper: {str(e)}")
        return {"success": False, "message": f"Error getting scan result: {str(e)}"}


# update_yara_rule
@mcp.tool(name="update_yara_rule")
def update_yara_rule_wrapper(params: str = "") -> Dict[str, Any]:
    """Wrapper for update_yara_rule tool that accepts a params string."""
    try:
        logger.info(f"update_yara_rule called with params: {params}")
        params_dict = parse_params(params)
        name = params_dict.get("name", "")
        content = params_dict.get("content", "")
        source = params_dict.get("source", "custom")

        logger.info(f"Parsed params: name={name}, source={source}, content length={len(content)}")
        return update_yara_rule_func(name, content, source)
    except Exception as e:
        logger.error(f"Error in update_yara_rule_wrapper: {str(e)}")
        return {"success": False, "message": str(e)}


# delete_yara_rule
@mcp.tool(name="delete_yara_rule")
def delete_yara_rule_wrapper(params: str = "") -> Dict[str, Any]:
    """Wrapper for delete_yara_rule tool that accepts a params string."""
    try:
        logger.info(f"delete_yara_rule called with params: {params}")
        params_dict = parse_params(params)
        name = params_dict.get("name", "")
        source = params_dict.get("source", "custom")

        logger.info(f"Parsed params: name={name}, source={source}")
        return delete_yara_rule_func(name, source)
    except Exception as e:
        logger.error(f"Error in delete_yara_rule_wrapper: {str(e)}")
        return {"success": False, "message": str(e)}


# import_threatflux_rules
@mcp.tool(name="import_threatflux_rules")
def import_threatflux_rules_wrapper(params: str = "") -> Dict[str, Any]:
    """Wrapper for import_threatflux_rules tool that accepts a params string."""
    try:
        logger.info(f"import_threatflux_rules called with params: {params}")
        params_dict = parse_params(params)
        url = params_dict.get("url", None)
        branch = params_dict.get("branch", "master")

        logger.info(f"Parsed params: url={url}, branch={branch}")
        return import_threatflux_rules_func(url, branch)
    except Exception as e:
        logger.error(f"Error in import_threatflux_rules_wrapper: {str(e)}")
        return {"success": False, "message": str(e)}


# get_storage_info
@mcp.tool(name="get_storage_info")
def get_storage_info_wrapper(params: str = "") -> Dict[str, Any]:
    """Wrapper for get_storage_info tool that accepts a params string."""
    try:
        logger.info(f"get_storage_info called with params: {params}")
        # This tool doesn't have any parameters, so we can just call it directly
        return get_storage_info_func()
    except Exception as e:
        logger.error(f"Error in get_storage_info_wrapper: {str(e)}")
        return {"success": False, "message": f"Error getting storage info: {str(e)}"}


# clean_storage
@mcp.tool(name="clean_storage")
def clean_storage_wrapper(params: str = "") -> Dict[str, Any]:
    """Wrapper for clean_storage tool that accepts a params string."""
    try:
        logger.info(f"clean_storage called with params: {params}")
        params_dict = parse_params(params)
        storage_type = params_dict.get("storage_type", "results")
        older_than_days_str = params_dict.get("older_than_days", None)
        older_than_days = int(older_than_days_str) if older_than_days_str else None

        logger.info(f"Parsed params: storage_type={storage_type}, older_than_days={older_than_days}")
        return clean_storage_func(storage_type, older_than_days)
    except Exception as e:
        logger.error(f"Error in clean_storage_wrapper: {str(e)}")
        return {"success": False, "message": f"Error cleaning storage: {str(e)}"}


@mcp.resource("rules://{source}")
def get_rules_list(source: str = "all") -> str:
    """Get a list of YARA rules.

    Args:
        source: Source filter ("custom", "community", or "all")

    Returns:
        Formatted list of rules
    """
    try:
        rules = yara_service.list_rules(None if source == "all" else source)
        if not rules:
            return "No YARA rules found."

        result = f"# YARA Rules ({source})\n\n"
        for rule in rules:
            result += f"- **{rule.name}**"
            if rule.description:
                result += f": {rule.description}"
            result += f" (Source: {rule.source})\n"

        return result
    except Exception as e:
        logger.error(f"Error getting rules list: {str(e)}")
        return f"Error getting rules list: {str(e)}"


@mcp.resource("rule://{name}/{source}")
def get_rule_content(name: str, source: str = "custom") -> str:
    """Get the content of a specific YARA rule.

    Args:
        name: Name of the rule
        source: Source of the rule ("custom" or "community")

    Returns:
        Rule content
    """
    try:
        content = yara_service.get_rule(name, source)
        return f"```yara\n{content}\n```"
    except Exception as e:
        logger.error(f"Error getting rule content: {str(e)}")
        return f"Error getting rule content: {str(e)}"


def initialize_server():
    """Initialize the MCP server environment."""
    import os

    from yaraflux_mcp_server.auth import init_user_db

    logger.info("Initializing YaraFlux MCP Server...")

    # Ensure directories exist
    directories = [
        settings.STORAGE_DIR,
        settings.YARA_RULES_DIR,
        settings.YARA_SAMPLES_DIR,
        settings.YARA_RESULTS_DIR,
        settings.YARA_RULES_DIR / "community",
        settings.YARA_RULES_DIR / "custom",
    ]

    for directory in directories:
        try:
            os.makedirs(directory, exist_ok=True)
            logger.info(f"Directory ensured: {directory}")
        except Exception as e:
            logger.error(f"Error creating directory {directory}: {str(e)}")
            raise

    # Initialize user database
    try:
        init_user_db()
        logger.info("User database initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing user database: {str(e)}")
        raise

    # Load YARA rules
    try:
        yara_service.load_rules(include_default_rules=settings.YARA_INCLUDE_DEFAULT_RULES)
        logger.info("YARA rules loaded successfully")
    except Exception as e:
        logger.error(f"Error loading YARA rules: {str(e)}")
        raise


async def list_registered_tools():
    """List all registered tools."""
    try:
        # Get tools using the async method properly
        tools = await mcp.list_tools()
        tool_names = [tool["name"] for tool in tools]
        logger.info(f"Available MCP tools: {tool_names}")
        return tool_names
    except Exception as e:
        logger.error(f"Error listing tools: {str(e)}")
        return []


def run_server(transport_mode="http"):
    """Run the MCP server with the specified transport mode."""
    try:
        initialize_server()

        # Set up connection handlers
        mcp.on_connect = lambda: logger.info("MCP connection established")
        mcp.on_disconnect = lambda: logger.info("MCP connection closed")

        # Don't try to list tools here as it's an async operation
        # We'll handle that separately when the server is running

        # Run with appropriate transport
        if transport_mode == "stdio":
            import asyncio

            from mcp.server.stdio import stdio_server

            async def run_stdio():
                async with stdio_server() as (read_stream, write_stream):
                    # Before the main run, we can list tools properly
                    await list_registered_tools()

                    # Now run the server
                    await mcp._mcp_server.run(
                        read_stream, write_stream, mcp._mcp_server.create_initialization_options()
                    )

            asyncio.run(run_stdio())
        else:
            # For HTTP mode, we need to handle the async method differently
            # since mcp.run() is not async itself
            asyncio.run(list_registered_tools())

            # Now run the server
            mcp.run()

    except Exception as e:
        logger.critical(f"Critical error during server operation: {str(e)}")
        raise


# Run the MCP server when executed directly
if __name__ == "__main__":
    import sys

    transport = "stdio" if "--transport" in sys.argv and "stdio" in sys.argv else "http"
    run_server(transport)
