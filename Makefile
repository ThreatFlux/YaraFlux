.PHONY: all clean install dev-setup test lint format docker-build docker-run mypy security-check coverage run import-rules lock sync

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

# Installation
install:
	@echo "Creating virtual environment and installing dependencies..."
	$(UV) venv --python $(PYTHON_VERSION)
	$(UV) pip install -e .
	@echo "Installation complete."

dev-setup: install
	@echo "Installing development dependencies..."
	$(UV) pip install -e ".[dev]"
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
	@echo "Running tests..."
	$(UV) run pytest -v tests/

coverage:
	@echo "Generating coverage report..."
	$(UV) run coverage run -m pytest tests/
	$(UV) run coverage report -m
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
	$(UV) run safety scan
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
	@echo "  all             : Clean, install, test, and lint"
	@echo "  clean           : Clean up build artifacts and caches"
	@echo "  install         : Install dependencies in a virtual environment"
	@echo "  dev-setup       : Set up development environment"
	@echo "  lock            : Generate lock file for reproducible builds"
	@echo "  sync            : Sync dependencies from lock file"
	@echo "  test            : Run tests"
	@echo "  coverage        : Generate test coverage report"
	@echo "  lint            : Run linters"
	@echo "  format          : Format code using Black and isort"
	@echo "  mypy            : Run type checker"
	@echo "  security-check  : Run security checks"
	@echo "  docker-build    : Build Docker image"
	@echo "  docker-run      : Run Docker container"
	@echo "  run             : Run development server"
	@echo "  import-rules    : Import ThreatFlux YARA rules"
	@echo ""
