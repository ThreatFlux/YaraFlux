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

- Python 3.11 or newer
- YARA library with development headers
- Optional: MinIO or S3-compatible storage

### Using pip

```bash
pip install yaraflux-mcp-server
```

### From source

```bash
git clone https://github.com/ThreatFlux/YaraFlux.git
cd YaraFlux/yaraflux_mcp_server
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
make docker-build

# Run the Docker container
make docker-run
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

### Option 1: Using the MCP CLI

The easiest way to install YaraFlux in Claude Desktop is using the MCP CLI:

```bash
# Install the MCP CLI if you don't have it
pip install "mcp[cli]"

# Install YaraFlux MCP Server
mcp install src/yaraflux_mcp_server/mcp_server.py --name "YaraFlux" \
    -v JWT_SECRET_KEY=your-jwt-secret \
    -v ADMIN_PASSWORD=your-admin-password
```

### Option 2: Using the Provided Script

We provide a convenience script that builds the Docker image and installs the server:

```bash
chmod +x install_claude.sh
./install_claude.sh
```

### Using YaraFlux with Claude

Once installed, you can interact with YaraFlux through Claude using natural language:

- "List all available YARA rules"
- "Validate this YARA rule: [rule content]"
- "Scan this URL for malware: https://example.com/file.txt"
- "Create a new YARA rule to detect [pattern]"
- "Delete the rule named 'suspicious_behavior'"

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
