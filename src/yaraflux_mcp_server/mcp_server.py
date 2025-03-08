"""YaraFlux MCP Server implementation using the official MCP SDK.

This module creates a proper MCP server that exposes YARA functionality
to Claude Desktop following the Model Context Protocol specification.
This version now uses the modular claude_mcp_tools package.
"""

import logging
import os
import base64
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path

from mcp.server.fastmcp import FastMCP, Context

from yaraflux_mcp_server.config import settings
from yaraflux_mcp_server.auth import init_user_db
from yaraflux_mcp_server.yara_service import yara_service, YaraError
from yaraflux_mcp_server.storage import get_storage_client

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Import all tools from the modular claude_mcp_tools package
# This will register them automatically with FastMCP
import yaraflux_mcp_server.claude_mcp_tools

# Create an MCP server
mcp = FastMCP(
    "YaraFlux",
    title="YaraFlux YARA Scanning Server",
    description="MCP server for YARA rule management and file scanning",
    version="0.1.0"
)


# Register additional tools directly with the FastMCP instance
# This ensures the tools are available when using FastMCP directly

@mcp.tool()
def get_hex_view(
    file_id: str,
    offset: int = 0,
    length: Optional[int] = None,
    bytes_per_line: int = 16
) -> Dict[str, Any]:
    """Get hexadecimal view of file content.
    
    This tool provides a hexadecimal representation of file content with optional ASCII view.
    It's useful for examining binary files or seeing the raw content of text files.
    
    Args:
        file_id: ID of the file
        offset: Starting offset in bytes
        length: Number of bytes to return (if None, a reasonable default is used)
        bytes_per_line: Number of bytes per line in output
        
    Returns:
        Hexadecimal representation of file content
    """
    try:
        storage = get_storage_client()
        result = storage.get_hex_view(file_id, offset, length, bytes_per_line)
        
        return {
            "success": True,
            "file_id": result.get("file_id"),
            "file_name": result.get("file_name"),
            "hex_content": result.get("hex_content"),
            "offset": result.get("offset", offset),
            "length": result.get("length", 0),
            "total_size": result.get("total_size", 0),
            "bytes_per_line": result.get("bytes_per_line", bytes_per_line)
        }
    except Exception as e:
        logger.error(f"Error getting hex view for file {file_id}: {str(e)}")
        return {
            "success": False,
            "message": f"Error getting hex view: {str(e)}"
        }


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
        settings.YARA_RULES_DIR / "custom"
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

def run_server(transport_mode="http"):
    """Run the MCP server with the specified transport mode."""
    try:
        initialize_server()
            
        # Set up connection handlers
        mcp.on_connect = lambda: logger.info("MCP connection established")
        mcp.on_disconnect = lambda: logger.info("MCP connection closed")
            
        # Run with appropriate transport
        if transport_mode == "stdio":
            import asyncio
            from mcp.server.stdio import stdio_server
            
            async def run_stdio():
                async with stdio_server() as (read_stream, write_stream):
                    await mcp._mcp_server.run(
                        read_stream,
                        write_stream,
                        mcp._mcp_server.create_initialization_options()
                    )
                    
            asyncio.run(run_stdio())
        else:
            mcp.run()
            
    except Exception as e:
        logger.critical(f"Critical error during server operation: {str(e)}")
        raise

# Run the MCP server when executed directly
if __name__ == "__main__":
    import sys
    transport = "stdio" if "--transport" in sys.argv and "stdio" in sys.argv else "http"
    run_server(transport)
