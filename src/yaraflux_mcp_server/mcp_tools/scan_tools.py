"""YARA scanning tools for Claude MCP integration.

This module provides tools for scanning files and URLs with YARA rules.
It uses standardized error handling and parameter validation.
"""

import base64
import logging
from typing import Any, Dict, List, Optional

from yaraflux_mcp_server.mcp_tools.base import register_tool
from yaraflux_mcp_server.storage import get_storage_client
from yaraflux_mcp_server.utils.error_handling import safe_execute
from yaraflux_mcp_server.yara_service import YaraError, yara_service

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

    Args:
        url: URL of the file to scan
        rule_names: Optional list of rule names to match (if None, match all)
        sources: Optional list of sources to match rules from (if None, match all)
        timeout: Optional timeout in seconds (if None, use default)

    Returns:
        Scan result containing file details, scan status, and any matches found
    """

    def _scan_url(
        url: str, rule_names: Optional[List[str]], sources: Optional[List[str]], timeout: Optional[int]
    ) -> Dict[str, Any]:
        """Implementation function for scan_url."""
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

    # Execute with standardized error handling
    return safe_execute(
        "scan_url",
        _scan_url,
        url=url,
        rule_names=rule_names,
        sources=sources,
        timeout=timeout,
        error_handlers={YaraError: lambda e: {"success": False, "message": str(e), "error_type": "YaraError"}},
    )


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

    def _scan_data(
        data: str,
        filename: str,
        encoding: str,
        rule_names: Optional[List[str]],
        sources: Optional[List[str]],
        timeout: Optional[int],
    ) -> Dict[str, Any]:
        """Implementation function for scan_data."""
        # Validate encoding
        if encoding not in ["base64", "text"]:
            raise ValueError(f"Unsupported encoding: {encoding}")

        # Decode the data
        if encoding == "base64":
            try:
                decoded_data = base64.b64decode(data)
            except Exception as e:
                raise ValueError(f"Invalid base64 data: {str(e)}")
        else:  # encoding == "text"
            decoded_data = data.encode("utf-8")

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

    # Execute with standardized error handling
    return safe_execute(
        "scan_data",
        _scan_data,
        data=data,
        filename=filename,
        encoding=encoding,
        rule_names=rule_names,
        sources=sources,
        timeout=timeout,
        error_handlers={
            YaraError: lambda e: {"success": False, "message": str(e), "error_type": "YaraError"},
            ValueError: lambda e: {"success": False, "message": str(e), "error_type": "ValueError"},
        },
    )


@register_tool()
def get_scan_result(scan_id: str) -> Dict[str, Any]:
    """Get a scan result by ID.

    Args:
        scan_id: ID of the scan result

    Returns:
        Scan result
    """

    def _get_scan_result(scan_id: str) -> Dict[str, Any]:
        """Implementation function for get_scan_result."""
        # Get the result from storage
        storage = get_storage_client()
        result_data = storage.get_result(scan_id)

        return {"success": True, "result": result_data}

    # Execute with standardized error handling
    return safe_execute("get_scan_result", _get_scan_result, scan_id=scan_id)
