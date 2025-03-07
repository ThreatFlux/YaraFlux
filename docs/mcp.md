# MCP Integration Guide

YaraFlux integrates with the Model Context Protocol (MCP) to provide YARA scanning capabilities to AI assistants and other MCP clients.

## Overview

The MCP integration enables:
- Direct YARA rule management
- File scanning via URL or data
- Result retrieval and analysis
- Seamless integration with AI workflows

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

### 1. list_yara_rules
List available YARA rules.

```json
// Input Schema
{
  "type": "object",
  "properties": {
    "source": {
      "type": "string",
      "enum": ["custom", "community"]
    }
  }
}

// Example Usage
{
  "source": "custom"
}
```

### 2. get_yara_rule
Get a YARA rule's content.

```json
// Input Schema
{
  "type": "object",
  "properties": {
    "rule_name": {
      "type": "string"
    },
    "source": {
      "type": "string",
      "default": "custom"
    }
  },
  "required": ["rule_name"]
}

// Example Usage
{
  "rule_name": "test_malware",
  "source": "custom"
}
```

### 3. validate_yara_rule
Validate a YARA rule.

```json
// Input Schema
{
  "type": "object",
  "properties": {
    "content": {
      "type": "string"
    }
  },
  "required": ["content"]
}

// Example Usage
{
  "content": "rule test { condition: true }"
}
```

### 4. add_yara_rule
Add a new YARA rule.

```json
// Input Schema
{
  "type": "object",
  "properties": {
    "name": {
      "type": "string"
    },
    "content": {
      "type": "string"
    },
    "source": {
      "type": "string",
      "default": "custom"
    }
  },
  "required": ["name", "content"]
}

// Example Usage
{
  "name": "test_rule",
  "content": "rule test { condition: true }",
  "source": "custom"
}
```

### 5. scan_url
Scan a file from a URL.

```json
// Input Schema
{
  "type": "object",
  "properties": {
    "url": {
      "type": "string"
    },
    "rule_names": {
      "type": "array",
      "items": {
        "type": "string"
      }
    },
    "sources": {
      "type": "array",
      "items": {
        "type": "string"
      }
    },
    "timeout": {
      "type": "integer"
    }
  },
  "required": ["url"]
}

// Example Usage
{
  "url": "https://example.com/file.txt",
  "rule_names": ["test_malware"],
  "timeout": 30
}
```

### 6. scan_data
Scan in-memory data.

```json
// Input Schema
{
  "type": "object",
  "properties": {
    "data": {
      "type": "string"
    },
    "filename": {
      "type": "string"
    },
    "encoding": {
      "type": "string",
      "default": "base64"
    },
    "rule_names": {
      "type": "array",
      "items": {
        "type": "string"
      }
    },
    "timeout": {
      "type": "integer"
    }
  },
  "required": ["data", "filename"]
}

// Example Usage
{
  "data": "SGVsbG8gV29ybGQ=",
  "filename": "test.txt",
  "rule_names": ["test_malware"]
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
