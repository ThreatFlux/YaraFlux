"""MCP tools for YaraFlux integration with Claude Desktop.

This module defines MCP tools using our custom Claude MCP implementation.
"""

import base64
import httpx
import json
import logging
import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Union, Any
from uuid import UUID

from yaraflux_mcp_server.claude_mcp import register_tool
from yaraflux_mcp_server.config import settings
from yaraflux_mcp_server.models import YaraRuleMetadata, YaraScanResult, ScanRequest
from yaraflux_mcp_server.yara_service import yara_service, YaraError
from yaraflux_mcp_server.storage import get_storage_client

# Configure logging
logger = logging.getLogger(__name__)


@register_tool
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


@register_tool
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


@register_tool
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


@register_tool
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


@register_tool
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


@register_tool
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


@register_tool
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
    
    For Claude Desktop users, this can be invoked with natural language like:
    "Can you scan this URL for malware: https://example.com/suspicious-file.exe"
    "Analyze https://example.com/document.pdf for malicious patterns"
    "Check if the file at this URL contains known threats: https://example.com/sample.exe"
    
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


@register_tool
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


@register_tool
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
