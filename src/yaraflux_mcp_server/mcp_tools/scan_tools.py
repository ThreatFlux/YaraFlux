"""YARA scanning tools for Claude MCP integration.

This module provides tools for scanning files and URLs with YARA rules.
"""

import base64
import logging
from typing import Any, Dict, List, Optional, Union
from uuid import UUID

from pydantic import HttpUrl

from ..storage import get_storage_client
from ..yara_service import YaraError, yara_service
from .base import register_tool

# Configure logging
logger = logging.getLogger(__name__)


@register_tool()
def scan_url(
    url: str, rule_names: Optional[List[str]] = None, sources: Optional[List[str]] = None, timeout: Optional[int] = None
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
            "match_count": len(result.matches),
        }
    except YaraError as e:
        logger.error(f"Error scanning URL {url}: {str(e)}")
        return {"success": False, "message": str(e)}
    except Exception as e:
        logger.error(f"Unexpected error scanning URL {url}: {str(e)}")
        return {"success": False, "message": f"Unexpected error: {str(e)}"}


@register_tool()
def scan_data(
    data: str,
    filename: str,
    encoding: str = "base64",
    rule_names: Optional[List[str]] = None,
    sources: Optional[List[str]] = None,
    timeout: Optional[int] = None,
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
            decoded_data = data.encode("utf-8")
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
            "match_count": len(result.matches),
        }
    except YaraError as e:
        logger.error(f"Error scanning data: {str(e)}")
        return {"success": False, "message": str(e)}
    except Exception as e:
        logger.error(f"Unexpected error scanning data: {str(e)}")
        return {"success": False, "message": f"Unexpected error: {str(e)}"}


@register_tool()
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

        return {"success": True, "result": result_data}
    except Exception as e:
        logger.error(f"Error getting scan result {scan_id}: {str(e)}")
        return {"success": False, "message": f"Error getting scan result: {str(e)}"}
