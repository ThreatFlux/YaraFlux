# YaraFlux MCP Server

A Model Context Protocol (MCP) server for YARA scanning, providing LLMs with capabilities to analyze files with YARA rules.

## Documentation

Comprehensive documentation is available in the [docs/](docs/) directory:

- [Installation Guide](docs/installation.md) - Detailed setup instructions
- [CLI Usage Guide](docs/cli.md) - Command-line interface documentation
- [API Reference](docs/api.md) - REST API endpoints and usage
- [YARA Rules Guide](docs/yara_rules.md) - Creating and managing YARA rules
- [MCP Integration](docs/mcp.md) - Model Context Protocol integration details
- [Examples](docs/examples.md) - Real-world usage examples

## Features

- 🔍 YARA scanning integration with the Model Context Protocol
- 📝 Comprehensive YARA rule management
- 🔐 JWT authentication for secure API access
- 🐳 Docker deployment support
- 📦 MinIO/S3 storage option for rules, samples and results
- 🔄 Auto-import of ThreatFlux YARA rules
- 🌐 RESTful API for rule management and scanning
- 🤖 Direct AI assistant integration via MCP
- 🔍 URL and data scanning capabilities
- 📊 Detailed scan results and analysis

## Quick Start

### Installation

```bash
# Using pip
pip install yaraflux-mcp-server

# From source
git clone https://github.com/ThreatFlux/YaraFlux.git
cd YaraFlux/
make install
```

### Basic Usage

1. Start the server:
```bash
# From Python package
yaraflux-mcp-server run

# From source
make run
```

2. Create a YARA rule:
```bash
yaraflux rules create test_rule --content '
rule test_rule {
    meta:
        description = "Test rule"
    strings:
        $test = "test" nocase
    condition:
        $test
}'
```

3. Scan a file:
```bash
yaraflux scan url https://example.com/file.txt --rules test_rule
```

## Docker Deployment

```bash
# Build the image
docker build -t yaraflux-mcp-server:latest .

# Run the container
docker run -i --rm \
  --env JWT_SECRET_KEY=your-secret-key \
  --env ADMIN_PASSWORD=your-admin-password \
  --env DEBUG=true \
  --env PYTHONUNBUFFERED=1 \
  yaraflux-mcp-server:latest
```

## Claude Desktop Integration

YaraFlux can be integrated with Claude Desktop for AI-assisted YARA rule management and scanning.

1. Build the Docker image:
```bash
docker build -t yaraflux-mcp-server:latest .
```

2. Add to Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "yaraflux-mcp-server": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--env",
        "JWT_SECRET_KEY=your-secret-key",
        "--env",
        "ADMIN_PASSWORD=your-admin-password",
        "--env",
        "DEBUG=true",
        "--env",
        "PYTHONUNBUFFERED=1",
        "yaraflux-mcp-server:latest"
      ],
      "timeout": 1200,
      "disabled": false,
      "autoApprove": [
        "scan_url",
        "scan_data",
        "list_yara_rules",
        "get_yara_rule"
      ],
      "pipeMode": "binary"
    }
  }
}
```

## Development

```bash
# Set up development environment
make dev-setup

# Run tests
make test

# Code quality checks
make lint
make format
make security-check
```

## Project Structure

```
yaraflux_mcp_server/
├── src/
│   └── yaraflux_mcp_server/
│       ├── app.py                 # FastAPI application
│       ├── auth.py                # JWT authentication
│       ├── config.py              # Configuration loader
│       ├── models.py              # Pydantic models
│       ├── mcp_server.py          # MCP server implementation
│       ├── run_mcp.py             # MCP server entry point
│       ├── storage.py             # Storage abstraction
│       ├── yara_service.py        # YARA management
│       └── routers/               # API routes
├── docs/                          # Documentation
├── tests/                         # Test suite
├── examples/                      # Examples
└── [other configuration files]
```

## API Documentation

Interactive API documentation available at:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

For detailed API documentation, see [API Reference](docs/api.md).

## License

MIT License
