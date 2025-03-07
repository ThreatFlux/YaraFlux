# YaraFlux MCP Server

A Model Context Protocol (MCP) server for YARA scanning, providing LLMs with capabilities to analyze files with YARA rules.

## Features

- 🔍 YARA scanning integration with the Model Context Protocol
- 🔐 JWT authentication for secure API access
- 🐳 Docker deployment support
- 📦 MinIO/S3 storage option for rules, samples and results
- 🔄 Auto-import of ThreatFlux YARA rules
- 🌐 RESTful API for rule management and scanning

## Installation

### Prerequisites

- Docker
- YARA library with development headers (only if building from source)
- Optional: MinIO or S3-compatible storage

### Using pip

```bash
pip install yaraflux-mcp-server
```

### From source

```bash
git clone https://github.com/ThreatFlux/YaraFlux.git
cd YaraFlux/
make install
```

## Configuration

Create a `.env` file based on the provided `.env.example`:

```bash
cp .env.example .env
```

Edit the `.env` file to set your configuration:

```
# Security
JWT_SECRET_KEY=your-jwt-secret-key
ADMIN_PASSWORD=your-secure-admin-password

# Storage
USE_MINIO=false  # Set to true to use MinIO
```

## Usage

### Running the server

```bash
# From Python package
yaraflux-mcp-server run

# From source
make run
```

### Docker

```bash
# Build the Docker image
docker build -t yaraflux-mcp-server:latest .

# Run the Docker container
docker run -i --rm \
  --env JWT_SECRET_KEY=your-secret-key \
  --env ADMIN_PASSWORD=your-admin-password \
  --env DEBUG=true \
  --env PYTHONUNBUFFERED=1 \
  yaraflux-mcp-server:latest
```

### Importing YARA rules

```bash
# Import ThreatFlux YARA rules
yaraflux-mcp-server import-rules
```

## API Documentation

Once the server is running, you can access the API documentation at:

- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## Claude Desktop Integration

YaraFlux MCP Server can be easily integrated with Claude Desktop for AI-assisted YARA rule management and scanning.

### Building and Installing for Claude Desktop

1. First, build the Docker image:

```bash
docker build -t yaraflux-mcp-server:latest .
```

2. Add the following configuration to your Claude Desktop config (located at `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

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

Make sure to replace:
- `your-secret-key` with a secure JWT secret key
- `your-admin-password` with a secure admin password

### Using YaraFlux with Claude

Once installed, you can interact with YaraFlux through Claude using the following capabilities:

- List YARA rules: This will display all available rules in the system
- Get rule details: View the content and metadata of specific rules
- Scan URLs: Analyze files from URLs using YARA rules
- Scan data: Analyze file content directly using YARA rules

These operations are auto-approved in the configuration for seamless interaction.

## Development

### Setting up the development environment

```bash
make dev-setup
```

### Running tests

```bash
make test
```

### Checking code quality

```bash
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
│       ├── auth.py                # JWT authentication and user management
│       ├── config.py              # Configuration settings loader
│       ├── models.py              # Pydantic models for requests/responses
│       ├── mcp_server.py          # MCP server implementation
│       ├── run_mcp.py             # MCP server entry point
│       ├── storage.py             # Storage abstraction (local or MinIO)
│       ├── yara_service.py        # YARA rule management and scanning
│       ├── __init__.py            # Package initialization
│       ├── __main__.py            # CLI entry point
│       └── routers/
│           ├── auth.py            # Authentication API routes
│           ├── rules.py           # YARA rule management API routes
│           ├── scan.py            # YARA scanning API routes
│           └── __init__.py
├── tests/                         # Test suite
├── examples/                      # Example configurations
├── Dockerfile                     # Docker configuration
├── install_claude.sh              # Claude Desktop installation script
├── Makefile                       # Build automation
├── pyproject.toml                 # Project metadata and dependencies
├── requirements.txt               # Core dependencies
└── requirements-dev.txt           # Development dependencies
```

## License

MIT License
