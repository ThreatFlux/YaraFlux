"""Storage utility tools for Claude MCP integration.

This module provides utility tools for storage operations that don't
fit neatly into the other categories.
"""

import logging
import os
from typing import Dict, List, Optional, Any
from pathlib import Path

from ..config import settings
from ..storage import get_storage_client, StorageError
from .base import register_tool

# Configure logging
logger = logging.getLogger(__name__)

@register_tool()
def get_storage_info() -> Dict[str, Any]:
    """Get information about the storage system.
    
    This tool returns details about the current storage configuration
    including storage type, directory paths, and capacity information.
    
    Returns:
        Storage system information
    """
    try:
        storage = get_storage_client()
        
        # Basic storage info
        info = {
            "storage_type": "minio" if settings.USE_MINIO else "local",
            "local_directories": {
                "rules": str(settings.YARA_RULES_DIR),
                "samples": str(settings.YARA_SAMPLES_DIR),
                "results": str(settings.YARA_RESULTS_DIR)
            }
        }
        
        # Add capacity info for local storage
        if not settings.USE_MINIO:
            try:
                rules_usage = _get_directory_usage(settings.YARA_RULES_DIR)
                samples_usage = _get_directory_usage(settings.YARA_SAMPLES_DIR)
                results_usage = _get_directory_usage(settings.YARA_RESULTS_DIR)
                
                info["usage"] = {
                    "rules": rules_usage,
                    "samples": samples_usage,
                    "results": results_usage,
                    "total": {
                        "file_count": rules_usage["file_count"] + samples_usage["file_count"] + results_usage["file_count"],
                        "size_bytes": rules_usage["size_bytes"] + samples_usage["size_bytes"] + results_usage["size_bytes"],
                        "size_human": _bytes_to_human(rules_usage["size_bytes"] + samples_usage["size_bytes"] + results_usage["size_bytes"])
                    }
                }
            except Exception as e:
                logger.error(f"Error getting directory usage: {str(e)}")
                info["usage"] = {"error": str(e)}
        
        return {
            "success": True,
            "info": info
        }
    except Exception as e:
        logger.error(f"Error getting storage info: {str(e)}")
        return {
            "success": False,
            "message": f"Error getting storage info: {str(e)}"
        }

@register_tool()
def clean_storage(storage_type: str = "results", older_than_days: Optional[int] = None) -> Dict[str, Any]:
    """Clean up old files from storage.
    
    This tool deletes old files from the specified storage area. It can be used
    to free up space by removing old scan results or samples.
    
    Args:
        storage_type: Type of storage to clean ("results", "samples", or "all")
        older_than_days: Delete files older than this many days (if None, delete all)
        
    Returns:
        Cleanup operation result
    """
    try:
        storage = get_storage_client()
        deleted_count = 0
        
        if storage_type == "results" or storage_type == "all":
            try:
                deleted = storage.clean_results(older_than_days)
                deleted_count += deleted
                logger.info(f"Deleted {deleted} result files")
            except Exception as e:
                logger.error(f"Error cleaning results: {str(e)}")
                return {
                    "success": False,
                    "message": f"Error cleaning results: {str(e)}"
                }
        
        if storage_type == "samples" or storage_type == "all":
            try:
                deleted = storage.clean_samples(older_than_days)
                deleted_count += deleted
                logger.info(f"Deleted {deleted} sample files")
            except Exception as e:
                logger.error(f"Error cleaning samples: {str(e)}")
                return {
                    "success": False,
                    "message": f"Error cleaning samples: {str(e)}"
                }
        
        return {
            "success": True,
            "message": f"Deleted {deleted_count} files",
            "deleted_count": deleted_count
        }
    except Exception as e:
        logger.error(f"Error cleaning storage: {str(e)}")
        return {
            "success": False,
            "message": f"Error cleaning storage: {str(e)}"
        }

def _get_directory_usage(directory: Path) -> Dict[str, Any]:
    """Get usage statistics for a directory.
    
    Args:
        directory: Directory path
        
    Returns:
        Usage statistics (file count, size)
    """
    total_size = 0
    file_count = 0
    
    for path, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(path, file)
            if os.path.isfile(file_path):
                total_size += os.path.getsize(file_path)
                file_count += 1
    
    return {
        "file_count": file_count,
        "size_bytes": total_size,
        "size_human": _bytes_to_human(total_size)
    }

def _bytes_to_human(size_bytes: int) -> str:
    """Convert bytes to human-readable size.
    
    Args:
        size_bytes: Size in bytes
        
    Returns:
        Human-readable size string
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024 or unit == 'TB':
            break
        size_bytes /= 1024.0
    
    return f"{size_bytes:.2f} {unit}"
