# MCP Integration Guide

YaraFlux integrates with the Model Context Protocol (MCP) to provide YARA scanning capabilities to AI assistants and other MCP clients.

## Overview

The MCP integration enables:
- Direct YARA rule management (create, read, update, delete)
- File scanning via URL or data with comprehensive rule matching
- Advanced file analysis including hex view and string extraction
- File management with upload, download, and metadata operations
- Storage statistics and maintenance functions
- Seamless integration with AI workflows through 19 specialized tools

## Server Configuration

### Setup

1. Install MCP server dependencies:
```bash
pip install mcp-sdk>=0.1.0
```

2. Configure environment variables:
```env
JWT_SECRET_KEY=your_jwt_secret_key
ADMIN_PASSWORD=your_admin_password
DEBUG=true  # Optional
```

3. Start the MCP server:
```bash
docker run -i --rm \
  --env JWT_SECRET_KEY=your_jwt_secret_key \
  --env ADMIN_PASSWORD=your_admin_password \
  --env DEBUG=true \
  --env PYTHONUNBUFFERED=1 \
  yaraflux-mcp-server:latest
```

## Available Tools

YaraFlux MCP Server provides 19 specialized tools organized into four categories:

### Rule Management Tools

#### 1. list_yara_rules
List available YARA rules.

```json
// Input Schema
{
  "source": "custom" // Optional: filter by source (custom, community, or all)
}

// Example Usage
{
  "source": "custom"
}

// Example Response
[
  {
    "name": "test_rule.yar",
    "source": "custom",
    "created": "2025-03-09T01:17:25.273527",
    "modified": "2025-03-09T01:17:25.273527",
    "tags": [],
    "is_compiled": true
  }
]
```

#### 2. get_yara_rule
Get a YARA rule's content.

```json
// Input Schema
{
  "rule_name": "test_rule.yar", // Required: name of the rule
  "source": "custom"            // Optional: source of the rule (default: custom)
}

// Example Response
{
  "name": "test_rule.yar",
  "source": "custom",
  "content": "rule test_rule { condition: true }",
  "metadata": { ... }
}
```

#### 3. validate_yara_rule
Validate a YARA rule.

```json
// Input Schema
{
  "content": "rule test { condition: true }" // Required: rule content to validate
}

// Example Response
{
  "valid": true,
  "message": "Rule is valid"
}
```

#### 4. add_yara_rule
Add a new YARA rule.

```json
// Input Schema
{
  "name": "test_rule",                     // Required: name for the rule
  "content": "rule test { condition: true }", // Required: rule content
  "source": "custom"                       // Optional: source (default: custom)
}

// Example Response
{
  "success": true,
  "message": "Rule test_rule added successfully",
  "metadata": { ... }
}
```

#### 5. update_yara_rule
Update an existing YARA rule.

```json
// Input Schema
{
  "name": "test_rule.yar",                  // Required: name of rule to update
  "content": "rule test { condition: true }", // Required: new rule content
  "source": "custom"                        // Optional: source (default: custom)
}

// Example Response
{
  "success": true,
  "message": "Rule test_rule.yar updated successfully",
  "metadata": { ... }
}
```

#### 6. delete_yara_rule
Delete an existing YARA rule.

```json
// Input Schema
{
  "name": "test_rule.yar", // Required: name of rule to delete
  "source": "custom"       // Optional: source (default: custom)
}

// Example Response
{
  "success": true,
  "message": "Rule test_rule.yar deleted successfully"
}
```

#### 7. import_threatflux_rules
Import YARA rules from the ThreatFlux repository.

```json
// Input Schema
{
  "url": "https://github.com/ThreatFlux/YARA-Rules", // Optional: URL to repository
  "branch": "master"                                 // Optional: branch name
}

// Example Response
{
  "success": true,
  "message": "Imported 12 rules from https://github.com/ThreatFlux/YARA-Rules (0 errors)",
  "import_count": 12,
  "error_count": 0
}
```

### Scanning Tools

#### 8. scan_url
Scan a file from a URL.

```json
// Input Schema
{
  "url": "https://example.com/file.txt",  // Required: URL to scan
  "rule_names": ["test_rule.yar"],        // Optional: specific rules to use
  "sources": ["custom", "community"],     // Optional: sources to use
  "timeout": 30                           // Optional: timeout in seconds
}

// Example Response
{
  "success": true,
  "scan_id": "fcfe3fd9-dbef-4b6c-9492-e50ec0fbab23",
  "file_name": "index.html",
  "file_size": 1256,
  "file_hash": "ea8fac7c65fb589b0d53560f5251f74f9e9b243478dcb6b3ea79b5e36449c8d9",
  "scan_time": 0.0015714168548583984,
  "timeout_reached": false,
  "matches": [],
  "match_count": 0
}
```

#### 9. scan_data
Scan in-memory data.

```json
// Input Schema
{
  "data": "SGVsbG8gV29ybGQ=",  // Required: data to scan (base64 encoded by default)
  "filename": "test.txt",      // Required: filename for reference
  "encoding": "base64",        // Optional: encoding of data (base64 or text)
  "rule_names": ["test_rule.yar"], // Optional: specific rules to use
  "sources": ["custom"],       // Optional: sources to use
  "timeout": 30                // Optional: timeout in seconds
}

// Example Response
{
  "success": true,
  "scan_id": "e6418eeb-702e-4f5c-8a94-de89d4be125c",
  "file_name": "test.txt",
  "file_size": 77,
  "file_hash": "221f86a9ebb3563dab78e929ba9abd06988555a96fecaa0f4e0e1a9e50450080",
  "scan_time": 0.00020766258239746094,
  "timeout_reached": false,
  "matches": [
    {
      "rule": "test_rule_mcp",
      "namespace": "default",
      "tags": [],
      "meta": {
        "author": "Test",
        "description": "Rule for testing MCP tools"
      },
      "strings": []
    }
  ],
  "match_count": 1
}
```

#### 10. get_scan_result
Get a scan result by ID.

```json
// Input Schema
{
  "scan_id": "e6418eeb-702e-4f5c-8a94-de89d4be125c" // Required: ID of scan result
}

// Example Response
{
  "success": true,
  "result": {
    "scan_id": "e6418eeb-702e-4f5c-8a94-de89d4be125c",
    "file_name": "scan_test.txt",
    "file_size": 77,
    "file_hash": "221f86a9ebb3563dab78e929ba9abd06988555a96fecaa0f4e0e1a9e50450080",
    "timestamp": "2025-03-09 01:17:56.516357",
    "matches": [{"rule": "test_rule_mcp", "namespace": "default", "tags": [], "meta": {"author": "Test", "description": "Rule for testing MCP tools"}, "strings": []}],
    "scan_time": 0.00020766258239746094,
    "timeout_reached": false,
    "error": null
  }
}
```

### File Management Tools

#### 11. upload_file
Upload a file for analysis.

```json
// Input Schema
{
  "data": "SGVsbG8gV29ybGQ=",  // Required: file content (base64 encoded by default)
  "file_name": "test.txt",     // Required: name for the uploaded file
  "encoding": "base64",        // Optional: encoding of data (base64 or text)
  "metadata": "{}"             // Optional: metadata as JSON string
}

// Example Response
{
  "success": true,
  "message": "File test.txt uploaded successfully",
  "file_info": {
    "file_id": "0fd4009d-4b3c-4be9-a355-254baa386128",
    "file_name": "test.txt",
    "file_size": 77,
    "file_hash": "221f86a9ebb3563dab78e929ba9abd06988555a96fecaa0f4e0e1a9e50450080",
    "mime_type": "text/plain",
    "uploaded_at": "2025-03-09T01:17:32.939299",
    "metadata": {}
  }
}
```

#### 12. get_file_info
Get detailed information about a file.

```json
// Input Schema
{
  "file_id": "0fd4009d-4b3c-4be9-a355-254baa386128" // Required: ID of file
}

// Example Response
{
  "success": true,
  "file_info": {
    "file_id": "0fd4009d-4b3c-4be9-a355-254baa386128",
    "file_name": "test.txt",
    "file_size": 77,
    "file_hash": "221f86a9ebb3563dab78e929ba9abd06988555a96fecaa0f4e0e1a9e50450080",
    "mime_type": "text/plain",
    "uploaded_at": "2025-03-09T01:17:32.939299",
    "metadata": {}
  }
}
```

#### 13. list_files
List uploaded files with pagination and sorting.

```json
// Input Schema
{
  "page": 1,              // Optional: page number (default: 1)
  "page_size": 10,        // Optional: items per page (default: 100)
  "sort_by": "uploaded_at", // Optional: field to sort by
  "sort_desc": "true"     // Optional: sort descending if true
}

// Example Response
{
  "success": true,
  "files": [
    {
      "file_id": "0fd4009d-4b3c-4be9-a355-254baa386128",
      "file_name": "test.txt",
      "file_size": 77,
      "file_hash": "221f86a9ebb3563dab78e929ba9abd06988555a96fecaa0f4e0e1a9e50450080",
      "mime_type": "text/plain",
      "uploaded_at": "2025-03-09T01:17:32.939299",
      "metadata": {}
    }
  ],
  "total": 1,
  "page": 1,
  "page_size": 10
}
```

#### 14. delete_file
Delete a file from storage.

```json
// Input Schema
{
  "file_id": "0fd4009d-4b3c-4be9-a355-254baa386128" // Required: ID of file to delete
}

// Example Response
{
  "success": true,
  "message": "File test.txt deleted successfully",
  "file_id": "0fd4009d-4b3c-4be9-a355-254baa386128"
}
```

#### 15. extract_strings
Extract strings from a file.

```json
// Input Schema
{
  "file_id": "0fd4009d-4b3c-4be9-a355-254baa386128", // Required: ID of file
  "min_length": 4,           // Optional: minimum string length (default: 4)
  "include_unicode": "true", // Optional: include Unicode strings 
  "include_ascii": "true",   // Optional: include ASCII strings
  "limit": null              // Optional: maximum strings to extract
}

// Example Response
{
  "success": true,
  "file_id": "0fd4009d-4b3c-4be9-a355-254baa386128",
  "file_name": "test.txt",
  "strings": [
    {
      "string": "Hello, this is a test file for string extraction. THIS_IS_A_TEST_STRING",
      "offset": 0,
      "string_type": "ascii"
    }
  ],
  "total_strings": 1,
  "min_length": 4,
  "include_unicode": true,
  "include_ascii": true
}
```

#### 16. get_hex_view
Get a hexadecimal view of file content.

```json
// Input Schema
{
  "file_id": "0fd4009d-4b3c-4be9-a355-254baa386128", // Required: ID of file
  "offset": 0,        // Optional: starting offset (default: 0)
  "length": null,     // Optional: bytes to display (default: auto)
  "bytes_per_line": 16 // Optional: bytes per line in output
}

// Example Response
{
  "success": true,
  "file_id": "0fd4009d-4b3c-4be9-a355-254baa386128",
  "file_name": "test.txt",
  "hex_content": "00000000  48 65 6c 6c 6f 2c 20 74 68 69 73 20 69 73 20 61  |Hello, this is a|\n00000010  20 74 65 73 74 20 66 69 6c 65 20 66 6f 72 20 73  | test file for s|...",
  "offset": 0,
  "length": 77,
  "total_size": 77,
  "bytes_per_line": 16
}
```

#### 17. download_file
Download a file's content.

```json
// Input Schema
{
  "file_id": "0fd4009d-4b3c-4be9-a355-254baa386128", // Required: ID of file to download
  "encoding": "text"  // Optional: encoding for output (base64 or text)
}

// Example Response
{
  "success": true,
  "file_id": "0fd4009d-4b3c-4be9-a355-254baa386128",
  "file_name": "test.txt",
  "file_size": 77,
  "mime_type": "text/plain",
  "data": "Hello, this is a test file for string extraction. THIS_IS_A_TEST_STRING",
  "encoding": "text"
}
```

### Storage Management Tools

#### 18. get_storage_info
Get information about the storage system.

```json
// Input Schema
{
  // No parameters required
}

// Example Response
{
  "success": true,
  "info": {
    "storage_type": "local",
    "local_directories": {
      "rules": "data/rules",
      "samples": "data/samples",
      "results": "data/results"
    },
    "usage": {
      "rules": {"file_count": 1, "size_bytes": 166, "size_human": "166.00 B"},
      "samples": {"file_count": 0, "size_bytes": 0, "size_human": "0.00 B"},
      "results": {"file_count": 1, "size_bytes": 552, "size_human": "552.00 B"},
      "total": {"file_count": 2, "size_bytes": 718, "size_human": "718.00 B"}
    }
  }
}
```

#### 19. clean_storage
Clean up storage by removing old files.

```json
// Input Schema
{
  "storage_type": "results",   // Required: type of storage to clean
  "older_than_days": 30        // Optional: remove files older than X days
}

// Example Response
{
  "success": true,
  "message": "Cleaned 3 files from results storage",
  "cleaned_count": 3,
  "freed_bytes": 1536
}
```

## Integration Examples

### 1. Python Integration

```python
from mcp.client import McpClient

async def scan_file():
    client = McpClient()
    
    # Connect to YaraFlux MCP server
    server = await client.connect_server("yaraflux")
    
    # Create a YARA rule
    add_rule_result = await server.call_tool(
        "add_yara_rule",
        {
            "name": "test_rule",
            "content": "rule test { condition: true }"
        }
    )
    
    # Scan a file
    scan_result = await server.call_tool(
        "scan_url",
        {
            "url": "https://example.com/file.txt",
            "rule_names": ["test_rule"]
        }
    )
    
    return scan_result
```

### 2. CLI Integration

```bash
# Add a rule using MCP
yaraflux mcp invoke add_yara_rule --params '{
    "name": "test_rule",
    "content": "rule test { condition: true }"
}'

# Scan a file using MCP
yaraflux mcp invoke scan_url --params '{
    "url": "https://example.com/file.txt",
    "rule_names": ["test_rule"]
}'
```

## Error Handling

The MCP server returns standard error codes and messages:

```json
{
    "error": {
        "code": "VALIDATION_ERROR",
        "message": "Invalid rule syntax"
    }
}
```

Common error codes:
- VALIDATION_ERROR: Invalid input parameters
- RULE_NOT_FOUND: Rule doesn't exist
- SCAN_FAILED: Scanning operation failed
- TIMEOUT: Operation timed out
- SERVER_ERROR: Internal server error

## Best Practices

1. **Rule Management**
   - Validate rules before adding
   - Use descriptive rule names
   - Document rules with metadata

2. **Scanning**
   - Set appropriate timeouts
   - Handle scan results asynchronously
   - Monitor scan status

3. **Error Handling**
   - Implement proper error handling
   - Log errors for debugging
   - Provide meaningful error messages

4. **Performance**
   - Batch operations when possible
   - Reuse rule compilations
   - Monitor resource usage

## Security Considerations

1. **Authentication**
   - Use JWT tokens for authentication
   - Rotate tokens regularly
   - Implement proper access control

2. **Input Validation**
   - Validate all input parameters
   - Sanitize file data
   - Check URL safety

3. **Resource Protection**
   - Implement rate limiting
   - Set reasonable timeouts
   - Monitor system resources

## Troubleshooting

Common issues and solutions:

1. **Connection Issues**
   ```python
   # Check server status
   yaraflux mcp tools
   ```

2. **Rule Validation Failures**
   ```python
   # Validate rule syntax
   yaraflux mcp invoke validate_yara_rule --params '{
       "content": "rule test { condition: true }"
   }'
   ```

3. **Scan Timeout**
   ```python
   # Increase timeout for large files
   yaraflux mcp invoke scan_url --params '{
       "url": "https://example.com/large_file.txt",
       "timeout": 120
   }'
