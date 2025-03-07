# YaraFlux MCP Server

![GitHub License](https://img.shields.io/github/license/ThreatFlux/YaraFlux)
![Python Version](https://img.shields.io/badge/python-3.13-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.104.1-009688)

A Model Context Protocol (MCP) server for YARA scanning, providing LLMs with capabilities to analyze files with YARA rules.

## 📋 Overview

YaraFlux MCP Server enables AI assistants to perform YARA rule-based threat analysis through a standardized Model Context Protocol interface. The server supports comprehensive rule management, secure scanning, and detailed result analysis.

## ✨ Features

- 🔍 YARA scanning integration with Model Context Protocol
- 📝 Comprehensive YARA rule management (create, edit, delete, import)
- 🔐 JWT authentication for secure API access
- 🐳 Docker deployment support with easy configuration
- 📦 MinIO/S3 storage option for rules, samples and results
- 🔄 Auto-import of ThreatFlux YARA rules
- 🌐 RESTful API with complete Swagger documentation
- 🤖 Direct AI assistant integration via MCP
- 🔍 URL and data scanning capabilities
- 📊 Detailed scan results with match highlighting

## 🚀 Quick Start

### Installation

```bash
# Using pip
pip install yaraflux-mcp-server

# From source
git clone https://github.com/ThreatFlux/YaraFlux.git
cd YaraFlux/
make install
```

### Running the Server

```bash
# From Python package
yaraflux-mcp-server run

# From source
make run
```

### Basic Usage

```bash
# Create a YARA rule
yaraflux rules create test_rule --content '
rule test_rule {
    meta:
        description = "Test rule"
    strings:
        $test = "test" nocase
    condition:
        $test
}'

# Scan a file
yaraflux scan url https://example.com/file.txt --rules test_rule
```

## 🐳 Docker Deployment

```bash
# Build the image
docker build -t yaraflux-mcp-server:latest .

# Run the container
docker run -p 8000:8000 \
  --env JWT_SECRET_KEY=your-secret-key \
  --env ADMIN_PASSWORD=your-admin-password \
  --env DEBUG=true \
  --env PYTHONUNBUFFERED=1 \
  yaraflux-mcp-server:latest
```

## 🧩 Claude Desktop Integration

YaraFlux seamlessly integrates with Claude Desktop for AI-assisted YARA rule management and scanning.

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

## 📚 Documentation

Comprehensive documentation is available in the [docs/](docs/) directory:

- [Installation Guide](docs/installation.md) - Detailed setup instructions
- [CLI Usage Guide](docs/cli.md) - Command-line interface documentation
- [API Reference](docs/api.md) - REST API endpoints and usage
- [YARA Rules Guide](docs/yara_rules.md) - Creating and managing YARA rules
- [MCP Integration](docs/mcp.md) - Model Context Protocol integration details
- [Examples](docs/examples.md) - Real-world usage examples

## 🧪 Development

```bash
# Set up development environment
make dev-setup

# Run tests
make test

# Code quality checks
make lint
make format
make mypy
make security-check

# Generate test coverage report
make coverage
```

## 🗂️ Project Structure

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

## 🌐 API Documentation

Interactive API documentation available at:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

For detailed API documentation, see [API Reference](docs/api.md).

## 📋 Available Make Commands

Run `make help` to see all available commands:

```
YaraFlux MCP Server Makefile

Available targets:
  all             : Clean, install, test, and lint
  clean           : Clean up build artifacts and caches
  install         : Install dependencies in a virtual environment
  dev-setup       : Set up development environment
  lock            : Generate lock file for reproducible builds
  sync            : Sync dependencies from lock file
  test            : Run tests
  coverage        : Generate test coverage report
  lint            : Run linters
  format          : Format code using Black and isort
  mypy            : Run type checker
  security-check  : Run security checks
  docker-build    : Build Docker image
  docker-run      : Run Docker container
  run             : Run development server
  import-rules    : Import ThreatFlux YARA rules
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.