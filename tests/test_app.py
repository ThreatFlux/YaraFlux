"""Tests for the FastAPI application."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from yaraflux_mcp_server.app import app, create_app
from yaraflux_mcp_server.auth import get_password_hash
from yaraflux_mcp_server.models import TokenData, User, UserInDB, UserRole

def test_app_creation():
    """Test FastAPI application creation."""
    test_app = create_app()
    assert isinstance(test_app, FastAPI)
    assert test_app.title == "YaraFlux MCP Server"

def test_health_check(test_client: TestClient):
    """Test health check endpoint."""
    response = test_client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}

def test_api_routers(test_client: TestClient):
    """Test API router endpoints."""
    # Auth router endpoints
    response = test_client.post("/api/v1/auth/token")
    assert response.status_code in (401, 422)  # Requires credentials

    # Rules router endpoints
    response = test_client.get("/api/v1/rules")
    assert response.status_code == 401  # Requires authentication

    # Scan router endpoints
    response = test_client.post("/api/v1/scan/url")
    assert response.status_code == 401  # Requires authentication

def test_cors_middleware(test_client: TestClient):
    """Test CORS middleware configuration."""
    headers = {
        "Origin": "http://localhost:3000",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "Content-Type",
    }
    
    response = test_client.options("/health", headers=headers)
    assert response.status_code == 200
    
    # Check CORS headers
    cors_headers = response.headers
    assert "access-control-allow-origin" in cors_headers
    assert "*" == cors_headers["access-control-allow-origin"]
    assert "access-control-allow-methods" in cors_headers
    assert "POST" in cors_headers["access-control-allow-methods"]

@pytest.mark.asyncio
async def test_exception_handler():
    """Test global exception handler."""
    from contextlib import asynccontextmanager
    
    @asynccontextmanager
    async def lifespan(app):
        yield
    
    # Create a new test app with error endpoint
    app = FastAPI(lifespan=lifespan)
    
    @app.get("/test/error")
    async def test_error():
        raise ValueError("Test error")
    
    test_client = TestClient(app)
    response = test_client.get("/test/error", headers={"Accept": "application/json"})
    
    assert response.status_code == 500
    error_data = response.json()
    assert error_data["error"] == "Internal server error"
    assert "Test error" in error_data["detail"]

@pytest.mark.asyncio
async def test_startup_event():
    """Test application startup event."""
    # Mock required dependencies
    mock_ensure_dirs = AsyncMock()
    mock_init_db = AsyncMock()
    mock_load_rules = AsyncMock()
    
    # Create app with mocked dependencies
    with patch("yaraflux_mcp_server.app.ensure_directories_exist", mock_ensure_dirs), \
         patch("yaraflux_mcp_server.app.init_user_db", mock_init_db), \
         patch("yaraflux_mcp_server.app.yara_service.load_rules", mock_load_rules):
        
        app = create_app()
        
        # Create lifespan context
        async with app.router.lifespan_context({"type": "lifespan"}) as _:
            pass
        
        # Verify startup tasks were called
        mock_ensure_dirs.assert_called_once()
        mock_init_db.assert_called_once()
        mock_load_rules.assert_called_once()

def test_mcp_endpoints(test_client: TestClient):
    """Test MCP integration endpoints."""
    # Test tools listing
    response = test_client.get("/mcp/v1/tools")
    assert response.status_code == 200
    tools = response.json()
    assert isinstance(tools, list)
    
    # Test tool execution
    tool_request = {
        "name": "list_yara_rules",
        "parameters": {}
    }
    response = test_client.post("/mcp/v1/execute", json=tool_request)
    assert response.status_code == 200
    result = response.json()
    assert "result" in result

def test_auth_integration(test_client: TestClient, test_user: UserInDB, test_auth_headers: dict):
    """Test authentication integration."""
    # Test accessing protected endpoint without token
    response = test_client.get("/api/v1/rules")
    assert response.status_code == 401
    
    # Test accessing protected endpoint with valid token
    response = test_client.get("/api/v1/rules", headers=test_auth_headers)
    assert response.status_code == 200

def test_admin_required_endpoints(test_client: TestClient, test_admin: UserInDB, admin_auth_headers: dict):
    """Test endpoints requiring admin privileges."""
    test_rule = """
    rule test {
        condition:
            true
    }
    """
    # Test admin-only endpoint with admin token
    response = test_client.post(
        "/api/v1/rules",
        headers=admin_auth_headers,
        json={"name": "test.yar", "content": test_rule}
    )
    assert response.status_code == 200

def test_error_responses(test_client: TestClient, test_auth_headers: dict):
    """Test error response handling."""
    # Test invalid request body - expect 422 for validation error
    response = test_client.post(
        "/api/v1/scan/url",
        headers=test_auth_headers,
        json={}
    )
    assert response.status_code == 422
    
    # Test invalid URL format
    response = test_client.post(
        "/api/v1/scan/url",
        headers=test_auth_headers,
        json={"url": "not-a-url"}
    )
    assert response.status_code == 422
    
    # Test non-existent YARA rule
    response = test_client.get(
        "/api/v1/rules/nonexistent.yar",
        headers=test_auth_headers
    )
    assert response.status_code == 404
