.PHONY: all clean install dev-setup test lint format docker-build docker-run mypy security-check coverage run import-rules lock sync check-deps

# Default target
all: clean install test lint

# Python settings
UV = uv
PYTHON_VERSION = 3.13
VENV = .venv

# Docker settings
IMAGE_NAME = threatflux/yaraflux-mcp-server
VERSION = $(shell cat src/yaraflux_mcp_server/__init__.py | grep __version__ | sed -e "s/__version__ = \"\(.*\)\"/\1/")
DOCKER_TAG = $(IMAGE_NAME):$(VERSION)

# System detection
OS = $(shell uname -s)
ifeq ($(OS),Linux)
    PACKAGE_MANAGER = $(shell command -v apt-get >/dev/null 2>&1 && echo "apt" || (command -v yum >/dev/null 2>&1 && echo "yum" || echo "unknown"))
endif

# Check dependencies
check-deps:
	@echo "Checking system dependencies..."
	@if [ "$(OS)" = "Linux" ]; then \
		if [ "$(PACKAGE_MANAGER)" = "apt" ]; then \
			if ! dpkg -l | grep -q "python$(PYTHON_VERSION)-dev"; then \
				echo "Python $(PYTHON_VERSION) development package is missing. Installing..."; \
				sudo apt-get update && sudo apt-get install -y python$(PYTHON_VERSION)-dev; \
			else \
				echo "Python $(PYTHON_VERSION) development package is already installed."; \
			fi; \
			if ! dpkg -l | grep -q "build-essential"; then \
				echo "build-essential is missing. Installing..."; \
				sudo apt-get update && sudo apt-get install -y build-essential; \
			fi; \
			if ! dpkg -l | grep -q "libssl-dev"; then \
				echo "libssl-dev is missing. Installing..."; \
				sudo apt-get update && sudo apt-get install -y libssl-dev; \
			fi; \
			if ! dpkg -l | grep -q "libyara-dev"; then \
				echo "libyara-dev is missing. Installing..."; \
				sudo apt-get update && sudo apt-get install -y libyara-dev; \
			fi; \
		elif [ "$(PACKAGE_MANAGER)" = "yum" ]; then \
			if ! rpm -qa | grep -q "python$(PYTHON_VERSION)-devel"; then \
				echo "Python $(PYTHON_VERSION) development package is missing. Installing..."; \
				sudo yum install -y python$(PYTHON_VERSION)-devel; \
			else \
				echo "Python $(PYTHON_VERSION) development package is already installed."; \
			fi; \
			if ! rpm -qa | grep -q "gcc"; then \
				echo "gcc is missing. Installing..."; \
				sudo yum install -y gcc; \
			fi; \
			if ! rpm -qa | grep -q "openssl-devel"; then \
				echo "openssl-devel is missing. Installing..."; \
				sudo yum install -y openssl-devel; \
			fi; \
			if ! rpm -qa | grep -q "yara-devel"; then \
				echo "yara-devel is missing. Trying to install..."; \
				sudo yum install -y yara-devel || echo "Warning: yara-devel not available. May need to build from source."; \
			fi; \
		else \
			echo "Unknown package manager. Please install Python $(PYTHON_VERSION) development package manually."; \
		fi; \
	elif [ "$(OS)" = "Darwin" ]; then \
		if ! command -v brew >/dev/null 2>&1; then \
			echo "Homebrew is not installed. Please install it from https://brew.sh/"; \
			exit 1; \
		fi; \
		if ! brew list python@$(PYTHON_VERSION) >/dev/null 2>&1; then \
			echo "Python $(PYTHON_VERSION) is missing. Installing..."; \
			brew install python@$(PYTHON_VERSION); \
		fi; \
		if ! brew list yara >/dev/null 2>&1; then \
			echo "Yara is missing. Installing..."; \
			brew install yara; \
		fi; \
		if ! brew list openssl >/dev/null 2>&1; then \
			echo "OpenSSL is missing. Installing..."; \
			brew install openssl; \
		fi; \
	else \
		echo "Unsupported OS. Please ensure you have Python $(PYTHON_VERSION) development packages installed."; \
	fi
	@echo "System dependency check complete."

# Installation
install: check-deps
	@echo "Creating virtual environment and installing dependencies..."
	@if command -v $(UV) >/dev/null 2>&1; then \
		echo "uv is already installed."; \
	else \
		echo "Installing uv..."; \
		if [ "$(OS)" = "Darwin" ] || [ "$(OS)" = "Linux" ]; then \
			curl -LsSf https://astral.sh/uv/install.sh | sh; \
		elif [ "$(OS)" = "Windows_NT" ]; then \
			powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"; \
		else \
			pip install uv; \
		fi; \
	fi
	$(UV) venv --python $(PYTHON_VERSION)
	
	# Set environment variables for compilation if needed
	@if [ "$(OS)" = "Darwin" ] && brew --prefix openssl >/dev/null 2>&1; then \
		OPENSSL_DIR=$$(brew --prefix openssl) \
		$(UV) pip install -e .; \
	else \
		$(UV) pip install -e .; \
	fi
	@echo "Installation complete."

# Development setup
dev-setup: install
	@echo "Installing development dependencies..."
	$(UV) pip install -e ".[dev]"
	@echo "Ensuring PyJWT is installed..."
	$(UV) pip install PyJWT
	$(UV) run pre-commit install
	@echo "Development setup complete."

# Generate lockfile for reproducible builds
lock:
	@echo "Generating lock file..."
	$(UV) lock
	@echo "Lock file generated."

# Sync dependencies from lockfile
sync:
	@echo "Syncing dependencies from lock file..."
	$(UV) sync
	@echo "Dependencies synced."

# Testing
test:
	@echo "Checking test dependencies..."
	$(UV) pip install PyJWT >/dev/null 2>&1 || true
	@echo "Running tests..."
	$(UV) run pytest -v tests/

coverage:
	@echo "Checking test dependencies..."
	$(UV) pip install PyJWT >/dev/null 2>&1 || true
	@echo "Generating coverage report..."
	rm -f .coverage htmlcov/* || true
	# Use the .coveragerc file directly instead of command-line args
	$(UV) run python -m pytest tests/
	$(UV) run coverage report
	$(UV) run coverage html
	@echo "Coverage report generated in htmlcov/"

# Code quality
lint:
	@echo "Running linters..."
	$(UV) run pylint --rcfile=.pylintrc src/yaraflux_mcp_server --fail-under=9
	@echo "Linting complete."

format:
	@echo "Formatting code..."
	$(UV) run black src tests
	$(UV) run isort src tests
	@echo "Formatting complete."

mypy:
	@echo "Running type checker..."
	$(UV) run mypy --config-file=mypy.ini src/yaraflux_mcp_server
	@echo "Type checking complete."

security-check:
	@echo "Running security checks..."
	$(UV) run bandit -r src/yaraflux_mcp_server -c bandit.yaml
	@echo "Security checks complete."

# Cleaning
clean:
	@echo "Cleaning up..."
	rm -rf $(VENV) *.egg-info dist build __pycache__ .pytest_cache .coverage htmlcov
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	@echo "Cleanup complete."

# Docker
docker-build:
	@echo "Building Docker image $(DOCKER_TAG)..."
	docker build -t $(DOCKER_TAG) .
	docker tag $(DOCKER_TAG) $(IMAGE_NAME):latest
	@echo "Docker build complete."

docker-run:
	@echo "Running Docker container..."
	docker run -p 8000:8000 \
	-e JWT_SECRET_KEY=your_jwt_secret_key \
	-e ADMIN_PASSWORD=your_admin_password \
	$(DOCKER_TAG)

# Development
run:
	@echo "Running development server..."
	$(UV) run -m uvicorn yaraflux_mcp_server.app:app --reload --host 0.0.0.0 --port 8000

import-rules:
	@echo "Importing ThreatFlux YARA rules..."
	$(UV) run python -m yaraflux_mcp_server import-rules
	@echo "Rules import complete."

help:
	@echo "YaraFlux MCP Server Makefile"
	@echo ""
	@echo "Available targets:"
	@echo " all : Clean, install, test, and lint"
	@echo " clean : Clean up build artifacts and caches"
	@echo " check-deps : Check and install system dependencies"
	@echo " install : Install dependencies in a virtual environment"
	@echo " dev-setup : Set up development environment"
	@echo " lock : Generate lock file for reproducible builds"
	@echo " sync : Sync dependencies from lock file"
	@echo " test : Run tests"
	@echo " coverage : Generate test coverage report"
	@echo " lint : Run linters"
	@echo " format : Format code using Black and isort"
	@echo " mypy : Run type checker"
	@echo " security-check : Run security checks"
	@echo " docker-build : Build Docker image"
	@echo " docker-run : Run Docker container"
	@echo " run : Run development server"
	@echo " import-rules : Import ThreatFlux YARA rules"
	@echo ""
