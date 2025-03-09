"""Parameter schemas for YaraFlux MCP Server.

This module defines JSON Schema for all MCP tools used in YaraFlux MCP Server,
providing a centralized location for tool parameter definitions.
"""

from typing import Any, Dict, List, Optional

# Common parameter types
STRING = str
INTEGER = int
BOOLEAN = bool
FLOAT = float

# Scan tool schemas
SCAN_URL_SCHEMA = {
    "url": {
        "type": STRING,
        "required": True,
        "description": "URL of the file to scan",
    },
    "rule_names": {
        "type": List[STRING],
        "required": False,
        "description": "Optional list of rule names to match (if None, match all)",
    },
    "sources": {
        "type": List[STRING],
        "required": False,
        "description": "Optional list of sources to match rules from (if None, match all)",
    },
    "timeout": {
        "type": INTEGER,
        "required": False,
        "description": "Optional timeout in seconds (if None, use default)",
    },
}

SCAN_DATA_SCHEMA = {
    "data": {
        "type": STRING,
        "required": True,
        "description": "Data to scan (base64-encoded by default)",
    },
    "filename": {
        "type": STRING,
        "required": True,
        "description": "Name of the file for reference",
    },
    "encoding": {
        "type": STRING,
        "required": False,
        "default": "base64",
        "description": "Encoding of the data ('base64' or 'text')",
    },
    "rule_names": {
        "type": List[STRING],
        "required": False,
        "description": "Optional list of rule names to match (if None, match all)",
    },
    "sources": {
        "type": List[STRING],
        "required": False,
        "description": "Optional list of sources to match rules from (if None, match all)",
    },
    "timeout": {
        "type": INTEGER,
        "required": False,
        "description": "Optional timeout in seconds (if None, use default)",
    },
}

GET_SCAN_RESULT_SCHEMA = {
    "scan_id": {
        "type": STRING,
        "required": True,
        "description": "ID of the scan result",
    },
}

# Rule tool schemas
LIST_YARA_RULES_SCHEMA = {
    "source": {
        "type": STRING,
        "required": False,
        "description": "Optional source filter ('custom' or 'community')",
    },
}

GET_YARA_RULE_SCHEMA = {
    "rule_name": {
        "type": STRING,
        "required": True,
        "description": "Name of the rule to get",
    },
    "source": {
        "type": STRING,
        "required": False,
        "default": "custom",
        "description": "Source of the rule ('custom' or 'community')",
    },
}

VALIDATE_YARA_RULE_SCHEMA = {
    "content": {
        "type": STRING,
        "required": True,
        "description": "YARA rule content to validate",
    },
}

ADD_YARA_RULE_SCHEMA = {
    "name": {
        "type": STRING,
        "required": True,
        "description": "Name of the rule",
    },
    "content": {
        "type": STRING,
        "required": True,
        "description": "YARA rule content",
    },
    "source": {
        "type": STRING,
        "required": False,
        "default": "custom",
        "description": "Source of the rule ('custom' or 'community')",
    },
}

UPDATE_YARA_RULE_SCHEMA = {
    "name": {
        "type": STRING,
        "required": True,
        "description": "Name of the rule",
    },
    "content": {
        "type": STRING,
        "required": True,
        "description": "Updated YARA rule content",
    },
    "source": {
        "type": STRING,
        "required": False,
        "default": "custom",
        "description": "Source of the rule ('custom' or 'community')",
    },
}

DELETE_YARA_RULE_SCHEMA = {
    "name": {
        "type": STRING,
        "required": True,
        "description": "Name of the rule",
    },
    "source": {
        "type": STRING,
        "required": False,
        "default": "custom",
        "description": "Source of the rule ('custom' or 'community')",
    },
}

IMPORT_THREATFLUX_RULES_SCHEMA = {
    "url": {
        "type": STRING,
        "required": False,
        "description": "URL to the GitHub repository (if None, use default ThreatFlux repository)",
    },
    "branch": {
        "type": STRING,
        "required": False,
        "default": "master",
        "description": "Branch name to import from",
    },
}

# File tool schemas
UPLOAD_FILE_SCHEMA = {
    "data": {
        "type": STRING,
        "required": True,
        "description": "File content encoded as specified by the encoding parameter",
    },
    "file_name": {
        "type": STRING,
        "required": True,
        "description": "Name of the file",
    },
    "encoding": {
        "type": STRING,
        "required": False,
        "default": "base64",
        "description": "Encoding of the data ('base64' or 'text')",
    },
    "metadata": {
        "type": Dict[str, Any],
        "required": False,
        "description": "Optional metadata to associate with the file",
    },
}

GET_FILE_INFO_SCHEMA = {
    "file_id": {
        "type": STRING,
        "required": True,
        "description": "ID of the file",
    },
}

LIST_FILES_SCHEMA = {
    "page": {
        "type": INTEGER,
        "required": False,
        "default": 1,
        "description": "Page number (1-based)",
    },
    "page_size": {
        "type": INTEGER,
        "required": False,
        "default": 100,
        "description": "Number of items per page",
    },
    "sort_by": {
        "type": STRING,
        "required": False,
        "default": "uploaded_at",
        "description": "Field to sort by (uploaded_at, file_name, file_size)",
    },
    "sort_desc": {
        "type": BOOLEAN,
        "required": False,
        "default": True,
        "description": "Sort in descending order if True",
    },
}

DELETE_FILE_SCHEMA = {
    "file_id": {
        "type": STRING,
        "required": True,
        "description": "ID of the file to delete",
    },
}

EXTRACT_STRINGS_SCHEMA = {
    "file_id": {
        "type": STRING,
        "required": True,
        "description": "ID of the file",
    },
    "min_length": {
        "type": INTEGER,
        "required": False,
        "default": 4,
        "description": "Minimum string length",
    },
    "include_unicode": {
        "type": BOOLEAN,
        "required": False,
        "default": True,
        "description": "Include Unicode strings",
    },
    "include_ascii": {
        "type": BOOLEAN,
        "required": False,
        "default": True,
        "description": "Include ASCII strings",
    },
    "limit": {
        "type": Optional[INTEGER],
        "required": False,
        "default": None,
        "description": "Maximum number of strings to return",
    },
}

GET_HEX_VIEW_SCHEMA = {
    "file_id": {
        "type": STRING,
        "required": True,
        "description": "ID of the file",
    },
    "offset": {
        "type": INTEGER,
        "required": False,
        "default": 0,
        "description": "Starting offset in bytes",
    },
    "length": {
        "type": Optional[INTEGER],
        "required": False,
        "default": None,
        "description": "Number of bytes to return (if None, a reasonable default is used)",
    },
    "bytes_per_line": {
        "type": INTEGER,
        "required": False,
        "default": 16,
        "description": "Number of bytes per line in output",
    },
}

DOWNLOAD_FILE_SCHEMA = {
    "file_id": {
        "type": STRING,
        "required": True,
        "description": "ID of the file to download",
    },
    "encoding": {
        "type": STRING,
        "required": False,
        "default": "base64",
        "description": "Encoding for the returned data ('base64' or 'text')",
    },
}

# Storage tool schemas
GET_STORAGE_INFO_SCHEMA = {}  # No parameters needed

CLEAN_STORAGE_SCHEMA = {
    "storage_type": {
        "type": STRING,
        "required": True,
        "description": "Type of storage to clean ('results', 'samples', or 'all')",
    },
    "older_than_days": {
        "type": Optional[INTEGER],
        "required": False,
        "description": "Remove files older than X days (if None, use default)",
    },
}

# All schemas in a dictionary for easy lookup
TOOL_SCHEMAS = {
    # Scan tools
    "scan_url": SCAN_URL_SCHEMA,
    "scan_data": SCAN_DATA_SCHEMA,
    "get_scan_result": GET_SCAN_RESULT_SCHEMA,
    # Rule tools
    "list_yara_rules": LIST_YARA_RULES_SCHEMA,
    "get_yara_rule": GET_YARA_RULE_SCHEMA,
    "validate_yara_rule": VALIDATE_YARA_RULE_SCHEMA,
    "add_yara_rule": ADD_YARA_RULE_SCHEMA,
    "update_yara_rule": UPDATE_YARA_RULE_SCHEMA,
    "delete_yara_rule": DELETE_YARA_RULE_SCHEMA,
    "import_threatflux_rules": IMPORT_THREATFLUX_RULES_SCHEMA,
    # File tools
    "upload_file": UPLOAD_FILE_SCHEMA,
    "get_file_info": GET_FILE_INFO_SCHEMA,
    "list_files": LIST_FILES_SCHEMA,
    "delete_file": DELETE_FILE_SCHEMA,
    "extract_strings": EXTRACT_STRINGS_SCHEMA,
    "get_hex_view": GET_HEX_VIEW_SCHEMA,
    "download_file": DOWNLOAD_FILE_SCHEMA,
    # Storage tools
    "get_storage_info": GET_STORAGE_INFO_SCHEMA,
    "clean_storage": CLEAN_STORAGE_SCHEMA,
}
