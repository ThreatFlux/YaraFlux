"""Legacy MCP tools module for YaraFlux integration with Claude Desktop.

This module is maintained for backward compatibility and now imports
from the new modular claude_mcp_tools package.
"""

import logging
from typing import Dict, List, Optional, Any

# Configure logging
logger = logging.getLogger(__name__)

# Import from new modular package
from .claude_mcp_tools.scan_tools import scan_url, scan_data, get_scan_result
from .claude_mcp_tools.rule_tools import (
    list_yara_rules, get_yara_rule, validate_yara_rule,
    add_yara_rule, update_yara_rule, delete_yara_rule,
    import_threatflux_rules
)
from .claude_mcp_tools.file_tools import (
    upload_file, get_file_info, list_files, delete_file,
    extract_strings, get_hex_view, download_file
)
from .claude_mcp_tools.storage_tools import get_storage_info, clean_storage

# Warning for deprecation
logger.warning(
    "The yaraflux_mcp_server.claude_mcp_tools module is deprecated. "
    "Please import from yaraflux_mcp_server.claude_mcp_tools package instead."
)

# Export all tools
__all__ = [
    # Scan tools
    'scan_url', 'scan_data', 'get_scan_result',
    
    # Rule tools
    'list_yara_rules', 'get_yara_rule', 'validate_yara_rule',
    'add_yara_rule', 'update_yara_rule', 'delete_yara_rule',
    'import_threatflux_rules',
    
    # File tools
    'upload_file', 'get_file_info', 'list_files', 'delete_file',
    'extract_strings', 'get_hex_view', 'download_file',
    
    # Storage tools
    'get_storage_info', 'clean_storage'
]
