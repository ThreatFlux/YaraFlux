"""File management tools for Claude MCP integration.

This module provides tools for file operations including uploading, downloading,
viewing hex dumps, and extracting strings from files.
"""

import base64
import hashlib
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from ..storage import get_storage_client
from .base import register_tool

# Configure logging
logger = logging.getLogger(__name__)


@register_tool()
def upload_file(
    data: str, file_name: str, encoding: str = "base64", metadata: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Upload a file to the storage system.

    This tool allows you to upload files with metadata for later retrieval and analysis.
    Files can be uploaded as base64-encoded data or plain text.

    Args:
        data: File content encoded as specified by the encoding parameter
        file_name: Name of the file
        encoding: Encoding of the data ("base64" or "text")
        metadata: Optional metadata to associate with the file

    Returns:
        File information including ID, size, and metadata
    """
    try:
        # Decode the data
        if encoding == "base64":
            try:
                decoded_data = base64.b64decode(data)
            except Exception as e:
                logger.error(f"Invalid base64 data: {str(e)}")
                return {"success": False, "message": f"Invalid base64 data: {str(e)}"}
        elif encoding == "text":
            decoded_data = data.encode("utf-8")
        else:
            return {"success": False, "message": f"Unsupported encoding: {encoding}"}

        # Save the file
        storage = get_storage_client()
        file_info = storage.save_file(file_name, decoded_data, metadata or {})

        return {"success": True, "message": f"File {file_name} uploaded successfully", "file_info": file_info}
    except Exception as e:
        logger.error(f"Error uploading file {file_name}: {str(e)}")
        return {"success": False, "message": f"Error uploading file: {str(e)}"}


@register_tool()
def get_file_info(file_id: str) -> Dict[str, Any]:
    """Get detailed information about a file.

    Args:
        file_id: ID of the file

    Returns:
        File information including metadata
    """
    try:
        storage = get_storage_client()
        file_info = storage.get_file_info(file_id)

        return {"success": True, "file_info": file_info}
    except Exception as e:
        logger.error(f"Error getting file info for {file_id}: {str(e)}")
        return {"success": False, "message": f"Error getting file info: {str(e)}"}


@register_tool()
def list_files(
    page: int = 1, page_size: int = 100, sort_by: str = "uploaded_at", sort_desc: bool = True
) -> Dict[str, Any]:
    """List files with pagination and sorting.

    Args:
        page: Page number (1-based)
        page_size: Number of items per page
        sort_by: Field to sort by (uploaded_at, file_name, file_size)
        sort_desc: Sort in descending order if True

    Returns:
        List of files with pagination info
    """
    try:
        storage = get_storage_client()
        result = storage.list_files(page, page_size, sort_by, sort_desc)

        return {
            "success": True,
            "files": result.get("files", []),
            "total": result.get("total", 0),
            "page": result.get("page", page),
            "page_size": result.get("page_size", page_size),
        }
    except Exception as e:
        logger.error(f"Error listing files: {str(e)}")
        return {"success": False, "message": f"Error listing files: {str(e)}"}


@register_tool()
def delete_file(file_id: str) -> Dict[str, Any]:
    """Delete a file from storage.

    Args:
        file_id: ID of the file to delete

    Returns:
        Deletion result
    """
    try:
        storage = get_storage_client()

        # Get file info first to include in response
        try:
            file_info = storage.get_file_info(file_id)
            file_name = file_info.get("file_name", "Unknown file")
        except:
            file_name = "Unknown file"

        # Delete the file
        result = storage.delete_file(file_id)

        if result:
            return {"success": True, "message": f"File {file_name} deleted successfully", "file_id": file_id}
        else:
            return {"success": False, "message": f"File {file_id} not found or could not be deleted"}
    except Exception as e:
        logger.error(f"Error deleting file {file_id}: {str(e)}")
        return {"success": False, "message": f"Error deleting file: {str(e)}"}


@register_tool()
def extract_strings(
    file_id: str,
    min_length: int = 4,
    include_unicode: bool = True,
    include_ascii: bool = True,
    limit: Optional[int] = None,
) -> Dict[str, Any]:
    """Extract strings from a file.

    This tool extracts ASCII and/or Unicode strings from a file with a specified minimum length.
    It's useful for analyzing binary files or looking for embedded text in files.

    Args:
        file_id: ID of the file
        min_length: Minimum string length
        include_unicode: Include Unicode strings
        include_ascii: Include ASCII strings
        limit: Maximum number of strings to return

    Returns:
        Extracted strings and metadata
    """
    try:
        storage = get_storage_client()
        result = storage.extract_strings(file_id, min_length, include_unicode, include_ascii, limit)

        return {
            "success": True,
            "file_id": result.get("file_id"),
            "file_name": result.get("file_name"),
            "strings": result.get("strings", []),
            "total_strings": result.get("total_strings", 0),
            "min_length": result.get("min_length", min_length),
            "include_unicode": result.get("include_unicode", include_unicode),
            "include_ascii": result.get("include_ascii", include_ascii),
        }
    except Exception as e:
        logger.error(f"Error extracting strings from file {file_id}: {str(e)}")
        return {"success": False, "message": f"Error extracting strings: {str(e)}"}


@register_tool()
def get_hex_view(
    file_id: str, offset: int = 0, length: Optional[int] = None, bytes_per_line: int = 16
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
            "bytes_per_line": result.get("bytes_per_line", bytes_per_line),
        }
    except Exception as e:
        logger.error(f"Error getting hex view for file {file_id}: {str(e)}")
        return {"success": False, "message": f"Error getting hex view: {str(e)}"}


@register_tool()
def download_file(file_id: str, encoding: str = "base64") -> Dict[str, Any]:
    """Download a file's content.

    This tool retrieves the content of a file, returning it in the specified encoding.

    Args:
        file_id: ID of the file to download
        encoding: Encoding for the returned data ("base64" or "text")

    Returns:
        File content and metadata
    """
    try:
        storage = get_storage_client()
        file_data = storage.get_file(file_id)
        file_info = storage.get_file_info(file_id)

        # Encode the data as requested
        if encoding == "base64":
            encoded_data = base64.b64encode(file_data).decode("ascii")
        elif encoding == "text":
            try:
                encoded_data = file_data.decode("utf-8")
            except UnicodeDecodeError:
                # If the file isn't valid utf-8 text, fall back to base64
                encoded_data = base64.b64encode(file_data).decode("ascii")
                encoding = "base64"  # Update encoding to reflect what was actually used
        else:
            return {"success": False, "message": f"Unsupported encoding: {encoding}"}

        return {
            "success": True,
            "file_id": file_id,
            "file_name": file_info.get("file_name"),
            "file_size": file_info.get("file_size"),
            "mime_type": file_info.get("mime_type"),
            "data": encoded_data,
            "encoding": encoding,
        }
    except Exception as e:
        logger.error(f"Error downloading file {file_id}: {str(e)}")
        return {"success": False, "message": f"Error downloading file: {str(e)}"}
