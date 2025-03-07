"""YaraFlux MCP Server implementation using the official MCP SDK.

This module creates a proper MCP server that exposes YARA functionality
to Claude Desktop following the Model Context Protocol specification.
"""

import logging
import base64
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from pathlib import Path

from mcp.server.fastmcp import FastMCP, Context

from yaraflux_mcp_server.config import settings
from yaraflux_mcp_server.models import YaraRuleMetadata, YaraScanResult
from yaraflux_mcp_server.yara_service import yara_service, YaraError
from yaraflux_mcp_server.storage import get_storage_client

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Create an MCP server
mcp = FastMCP(
    "YaraFlux",
    title="YaraFlux YARA Scanning Server",
    description="MCP server for YARA rule management and file scanning",
    version="0.1.0"
)


@mcp.tool()
def list_yara_rules(source: Optional[str] = None) -> List[Dict[str, Any]]:
    """List available YARA rules.
    
    Args:
        source: Optional source filter ("custom" or "community")
        
    Returns:
        List of YARA rule metadata objects
    """
    try:
        # Get rules from the YARA service
        rules = yara_service.list_rules(source)
        
        # Convert to dict for serialization
        return [rule.dict() for rule in rules]
    except YaraError as e:
        logger.error(f"Error listing YARA rules: {str(e)}")
        return []


@mcp.tool()
def get_yara_rule(rule_name: str, source: str = "custom") -> Dict[str, Any]:
    """Get a YARA rule's content.
    
    Args:
        rule_name: Name of the rule to get
        source: Source of the rule ("custom" or "community")
        
    Returns:
        Rule content and metadata
    """
    try:
        # Get rule content
        content = yara_service.get_rule(rule_name, source)
        
        # Get rule metadata
        rules = yara_service.list_rules(source)
        metadata = None
        for rule in rules:
            if rule.name == rule_name:
                metadata = rule
                break
        
        # Return content and metadata
        return {
            "name": rule_name,
            "source": source,
            "content": content,
            "metadata": metadata.dict() if metadata else {}
        }
    except YaraError as e:
        logger.error(f"Error getting YARA rule {rule_name}: {str(e)}")
        return {
            "name": rule_name,
            "source": source,
            "error": str(e)
        }


@mcp.tool()
def validate_yara_rule(content: str) -> Dict[str, Any]:
    """Validate a YARA rule.
    
    Args:
        content: YARA rule content to validate
        
    Returns:
        Validation result
    """
    try:
        # Create a temporary rule name for validation
        temp_rule_name = f"validate_{int(datetime.utcnow().timestamp())}.yar"
        
        # Attempt to add the rule (this will validate it)
        yara_service.add_rule(temp_rule_name, content)
        
        # Rule is valid, delete it
        yara_service.delete_rule(temp_rule_name)
        
        return {
            "valid": True,
            "message": "Rule is valid"
        }
    except YaraError as e:
        logger.error(f"YARA rule validation error: {str(e)}")
        return {
            "valid": False,
            "message": str(e)
        }


@mcp.tool()
def add_yara_rule(
    name: str, 
    content: str, 
    source: str = "custom"
) -> Dict[str, Any]:
    """Add a new YARA rule.
    
    Args:
        name: Name of the rule
        content: YARA rule content
        source: Source of the rule ("custom" or "community")
        
    Returns:
        Result of the operation
    """
    try:
        # Add the rule
        metadata = yara_service.add_rule(name, content, source)
        
        return {
            "success": True,
            "message": f"Rule {name} added successfully",
            "metadata": metadata.dict()
        }
    except YaraError as e:
        logger.error(f"Error adding YARA rule {name}: {str(e)}")
        return {
            "success": False,
            "message": str(e)
        }


@mcp.tool()
def update_yara_rule(
    name: str, 
    content: str, 
    source: str = "custom"
) -> Dict[str, Any]:
    """Update an existing YARA rule.
    
    Args:
        name: Name of the rule
        content: Updated YARA rule content
        source: Source of the rule ("custom" or "community")
        
    Returns:
        Result of the operation
    """
    try:
        # Update the rule
        metadata = yara_service.update_rule(name, content, source)
        
        return {
            "success": True,
            "message": f"Rule {name} updated successfully",
            "metadata": metadata.dict()
        }
    except YaraError as e:
        logger.error(f"Error updating YARA rule {name}: {str(e)}")
        return {
            "success": False,
            "message": str(e)
        }


@mcp.tool()
def delete_yara_rule(
    name: str, 
    source: str = "custom"
) -> Dict[str, Any]:
    """Delete a YARA rule.
    
    Args:
        name: Name of the rule
        source: Source of the rule ("custom" or "community")
        
    Returns:
        Result of the operation
    """
    try:
        # Delete the rule
        result = yara_service.delete_rule(name, source)
        
        if result:
            return {
                "success": True,
                "message": f"Rule {name} deleted successfully"
            }
        else:
            return {
                "success": False,
                "message": f"Rule {name} not found"
            }
    except YaraError as e:
        logger.error(f"Error deleting YARA rule {name}: {str(e)}")
        return {
            "success": False,
            "message": str(e)
        }


@mcp.tool()
def scan_url(
    url: str,
    rule_names: Optional[List[str]] = None,
    sources: Optional[List[str]] = None,
    timeout: Optional[int] = None
) -> Dict[str, Any]:
    """Scan a file from a URL with YARA rules.
    
    This function downloads and scans a file from the provided URL using YARA rules.
    It's particularly useful for scanning potentially malicious files without storing
    them locally on the user's machine.
    
    Args:
        url: URL of the file to scan
        rule_names: Optional list of rule names to match (if None, match all)
        sources: Optional list of sources to match rules from (if None, match all)
        timeout: Optional timeout in seconds (if None, use default)
        
    Returns:
        Scan result containing file details, scan status, and any matches found
    """
    try:
        # Fetch and scan the file
        result = yara_service.fetch_and_scan(url, rule_names, sources, timeout)
        
        return {
            "success": True,
            "scan_id": str(result.scan_id),
            "file_name": result.file_name,
            "file_size": result.file_size,
            "file_hash": result.file_hash,
            "scan_time": result.scan_time,
            "timeout_reached": result.timeout_reached,
            "matches": [match.dict() for match in result.matches],
            "match_count": len(result.matches)
        }
    except YaraError as e:
        logger.error(f"Error scanning URL {url}: {str(e)}")
        return {
            "success": False,
            "message": str(e)
        }
    except Exception as e:
        logger.error(f"Unexpected error scanning URL {url}: {str(e)}")
        return {
            "success": False,
            "message": f"Unexpected error: {str(e)}"
        }


@mcp.tool()
def scan_data(
    data: str,
    filename: str,
    encoding: str = "base64",
    rule_names: Optional[List[str]] = None,
    sources: Optional[List[str]] = None,
    timeout: Optional[int] = None
) -> Dict[str, Any]:
    """Scan in-memory data with YARA rules.
    
    Args:
        data: Data to scan (base64-encoded by default)
        filename: Name of the file for reference
        encoding: Encoding of the data ("base64" or "text")
        rule_names: Optional list of rule names to match (if None, match all)
        sources: Optional list of sources to match rules from (if None, match all)
        timeout: Optional timeout in seconds (if None, use default)
        
    Returns:
        Scan result
    """
    try:
        # Decode the data
        if encoding == "base64":
            decoded_data = base64.b64decode(data)
        elif encoding == "text":
            decoded_data = data.encode('utf-8')
        else:
            raise ValueError(f"Unsupported encoding: {encoding}")
        
        # Scan the data
        result = yara_service.match_data(decoded_data, filename, rule_names, sources, timeout)
        
        return {
            "success": True,
            "scan_id": str(result.scan_id),
            "file_name": result.file_name,
            "file_size": result.file_size,
            "file_hash": result.file_hash,
            "scan_time": result.scan_time,
            "timeout_reached": result.timeout_reached,
            "matches": [match.dict() for match in result.matches],
            "match_count": len(result.matches)
        }
    except YaraError as e:
        logger.error(f"Error scanning data: {str(e)}")
        return {
            "success": False,
            "message": str(e)
        }
    except Exception as e:
        logger.error(f"Unexpected error scanning data: {str(e)}")
        return {
            "success": False,
            "message": f"Unexpected error: {str(e)}"
        }


@mcp.tool()
def get_scan_result(scan_id: str) -> Dict[str, Any]:
    """Get a scan result by ID.
    
    Args:
        scan_id: ID of the scan result
        
    Returns:
        Scan result
    """
    try:
        # Get the result from storage
        storage = get_storage_client()
        result_data = storage.get_result(scan_id)
        
        return {
            "success": True,
            "result": result_data
        }
    except Exception as e:
        logger.error(f"Error getting scan result {scan_id}: {str(e)}")
        return {
            "success": False,
            "message": str(e)
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
