"""Tests for authentication functionality."""

import pytest
from fastapi.testclient import TestClient

from yaraflux_mcp_server.models import UserRole


def test_login(test_client: TestClient):
    """Test login with valid credentials."""
    response = test_client.post(
        "/api/v1/auth/token",
        data={"username": "admin", "password": "test_admin_password"}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


def test_login_invalid_credentials(test_client: TestClient):
    """Test login with invalid credentials."""
    response = test_client.post(
        "/api/v1/auth/token",
        data={"username": "admin", "password": "wrong_password"}
    )
    
    assert response.status_code == 401
    data = response.json()
    assert "detail" in data


def test_get_current_user(test_client: TestClient, auth_headers):
    """Test getting current user information."""
    response = test_client.get("/api/v1/auth/users/me", headers=auth_headers)
    
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "admin"
    assert data["role"] == UserRole.ADMIN


def test_get_current_user_no_auth(test_client: TestClient):
    """Test getting current user without authentication."""
    response = test_client.get("/api/v1/auth/users/me")
    
    assert response.status_code == 401
    data = response.json()
    assert "detail" in data


def test_list_users(test_client: TestClient, auth_headers):
    """Test listing all users."""
    response = test_client.get("/api/v1/auth/users", headers=auth_headers)
    
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 1
    assert any(user["username"] == "admin" for user in data)


def test_create_user(test_client: TestClient, auth_headers):
    """Test creating a new user."""
    response = test_client.post(
        "/api/v1/auth/users",
        params={
            "username": "testuser",
            "password": "testpassword",
            "role": UserRole.USER,
            "email": "test@example.com"
        },
        headers=auth_headers
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "testuser"
    assert data["role"] == UserRole.USER
    assert data["email"] == "test@example.com"
    
    # Check that user was created
    response = test_client.get("/api/v1/auth/users", headers=auth_headers)
    data = response.json()
    assert any(user["username"] == "testuser" for user in data)


def test_create_duplicate_user(test_client: TestClient, auth_headers):
    """Test creating a user with a duplicate username."""
    # First create a user
    test_client.post(
        "/api/v1/auth/users",
        params={
            "username": "duplicateuser",
            "password": "testpassword"
        },
        headers=auth_headers
    )
    
    # Try to create again with same username
    response = test_client.post(
        "/api/v1/auth/users",
        params={
            "username": "duplicateuser",
            "password": "testpassword"
        },
        headers=auth_headers
    )
    
    assert response.status_code == 400
    data = response.json()
    assert "detail" in data
