"""Common test fixtures and configuration."""

import os
import tempfile
from datetime import datetime, timedelta, UTC
from typing import Dict, Generator
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from jose import jwt

from yaraflux_mcp_server.app import app
from yaraflux_mcp_server.auth import UserInDB, UserRole, create_user, init_user_db, _user_db
from yaraflux_mcp_server.config import settings
from yaraflux_mcp_server.storage import StorageClient
from yaraflux_mcp_server.yara_service import YaraService, yara_service

@pytest.fixture(autouse=True)
def init_test_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Initialize test environment."""
    # Set test environment variables
    monkeypatch.setenv("JWT_SECRET_KEY", "test_secret_key")
    monkeypatch.setenv("ADMIN_PASSWORD", "test_admin_pass")
    monkeypatch.setenv("STORAGE_DIR", "test_data")
    monkeypatch.setenv("YARA_RULES_DIR", "test_data/rules")
    monkeypatch.setenv("YARA_SAMPLES_DIR", "test_data/samples")
    monkeypatch.setenv("YARA_RESULTS_DIR", "test_data/results")
    
    # Create test directories
    os.makedirs("test_data/rules/custom", exist_ok=True)
    os.makedirs("test_data/rules/community", exist_ok=True)
    os.makedirs("test_data/samples", exist_ok=True)
    os.makedirs("test_data/results", exist_ok=True)
    
    # Clear user database
    _user_db.clear()
    init_user_db()

@pytest.fixture
def test_client(init_test_env) -> TestClient:
    """Create a test client for the FastAPI app."""
    return TestClient(app)

@pytest.fixture
def test_yara_rule() -> str:
    """Return a simple test YARA rule."""
    return """
    rule test_rule {
        meta:
            description = "Test rule for unit tests"
            author = "Test Author"
        strings:
            $test = "test string"
        condition:
            $test
    }
    """

@pytest.fixture
def mock_storage() -> MagicMock:
    """Create a mock storage client."""
    storage = MagicMock(spec=StorageClient)
    
    # Setup default responses
    storage.get_rule.return_value = ""
    storage.list_rules.return_value = []
    storage.save_rule.return_value = None
    storage.delete_rule.return_value = True
    
    return storage

@pytest.fixture
def setup_mock_storage(mock_storage: MagicMock, test_yara_rule: str) -> MagicMock:
    """Set up mock storage with test rule."""
    mock_storage.get_rule.return_value = test_yara_rule
    mock_storage.list_rules.return_value = [
        {"name": "test_rule.yar", "source": "custom", "created": datetime.now(UTC)}
    ]
    
    # Patch the yara_service's storage
    yara_service.storage = mock_storage
    return mock_storage

@pytest.fixture
def mock_yara_service(mock_storage: MagicMock) -> YaraService:
    """Create a YaraService instance with mock storage."""
    return YaraService(storage_client=mock_storage)

@pytest.fixture
def temp_dir() -> Generator[str, None, None]:
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        yield tmp_dir

@pytest.fixture
def test_user(init_test_env) -> UserInDB:
    """Create a test user."""
    test_password = "testpass"
    user = create_user(
        username="testuser",
        password=test_password,
        role=UserRole.USER
    )
    return user

@pytest.fixture
def test_admin(init_test_env) -> UserInDB:
    """Create a test admin user."""
    test_password = "testpass"
    admin = create_user(
        username="testadmin",
        password=test_password,
        role=UserRole.ADMIN
    )
    return admin

@pytest.fixture
def test_token(test_user: UserInDB) -> str:
    """Create a JWT token for the test user."""
    access_token_expires = timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {
        "sub": test_user.username,
        "role": test_user.role.value,
        "exp": datetime.now(UTC) + access_token_expires,
    }
    encoded_jwt = jwt.encode(
        to_encode,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )
    return encoded_jwt

@pytest.fixture
def admin_token(test_admin: UserInDB) -> str:
    """Create a JWT token for the admin user."""
    access_token_expires = timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {
        "sub": test_admin.username,
        "role": test_admin.role.value,
        "exp": datetime.now(UTC) + access_token_expires,
    }
    encoded_jwt = jwt.encode(
        to_encode,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )
    return encoded_jwt

@pytest.fixture
def test_auth_headers(test_token: str) -> Dict[str, str]:
    """Create authorization headers with the test token."""
    return {"Authorization": f"Bearer {test_token}"}

@pytest.fixture
def admin_auth_headers(admin_token: str) -> Dict[str, str]:
    """Create authorization headers with the admin token."""
    return {"Authorization": f"Bearer {admin_token}"}
