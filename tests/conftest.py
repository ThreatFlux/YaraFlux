"""Test configuration for YaraFlux MCP Server tests."""

import os
import tempfile
from pathlib import Path
from typing import Dict, Generator

import pytest
from fastapi.testclient import TestClient

# Set test environment variables
os.environ["JWT_SECRET_KEY"] = "test_secret_key"
os.environ["ADMIN_PASSWORD"] = "test_admin_password"
os.environ["DEBUG"] = "true"
os.environ["YARA_INCLUDE_DEFAULT_RULES"] = "false"


@pytest.fixture
def test_temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as temp_dir:
        # Set test storage directory
        os.environ["STORAGE_DIR"] = temp_dir
        
        # Create subdirectories
        rules_dir = Path(temp_dir) / "rules"
        rules_dir.mkdir()
        (rules_dir / "custom").mkdir()
        (rules_dir / "community").mkdir()
        
        samples_dir = Path(temp_dir) / "samples"
        samples_dir.mkdir()
        
        results_dir = Path(temp_dir) / "results"
        results_dir.mkdir()
        
        yield Path(temp_dir)


@pytest.fixture
def test_client(test_temp_dir: Path) -> TestClient:
    """Create a test client for the FastAPI app."""
    # Import app here to avoid circular imports
    from yaraflux_mcp_server.app import app
    
    return TestClient(app)


@pytest.fixture
def auth_headers(test_client: TestClient) -> Dict[str, str]:
    """Get authentication headers with a valid token."""
    response = test_client.post(
        "/api/v1/auth/token",
        data={"username": "admin", "password": "test_admin_password"}
    )
    
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def sample_yara_rule() -> str:
    """Get a sample YARA rule for testing."""
    return """
    rule TestRule {
        meta:
            description = "Test rule for YaraFlux MCP Server"
            author = "Test Author"
        strings:
            $test_string = "test string"
        condition:
            $test_string
    }
    """
