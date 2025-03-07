"""Tests for the authentication module."""

from datetime import datetime, timedelta, UTC
from unittest.mock import patch

import pytest
from fastapi import HTTPException
from fastapi.security import OAuth2PasswordRequestForm

from yaraflux_mcp_server.auth import (
    authenticate_user,
    create_access_token,
    create_user,
    delete_user,
    get_current_user,
    get_password_hash,
    get_user,
    init_user_db,
    list_users,
    update_user,
    validate_admin,
    verify_password,
    _user_db,
)
from yaraflux_mcp_server.models import UserRole

@pytest.fixture(autouse=True)
def clear_users():
    """Clear user database before each test."""
    _user_db.clear()
    init_user_db()

def test_password_hashing():
    """Test password hashing and verification."""
    password = "testpassword123"
    hashed = get_password_hash(password)
    
    assert verify_password(password, hashed)
    assert not verify_password("wrongpassword", hashed)

def test_create_user(clear_users):
    """Test user creation."""
    username = "newuser"
    password = "userpass123"
    
    # Create user
    user = create_user(username, password)
    assert user.username == username
    assert user.role == UserRole.USER
    assert not user.disabled
    
    # Verify user was created
    stored_user = get_user(username)
    assert stored_user is not None
    assert stored_user.username == username
    assert verify_password(password, stored_user.hashed_password)
    
    # Test duplicate creation
    with pytest.raises(ValueError):
        create_user(username, password)

def test_authenticate_user(clear_users):
    """Test user authentication."""
    username = "authuser"
    password = "authpass123"
    
    # Create test user
    create_user(username, password)
    
    # Test successful authentication
    user = authenticate_user(username, password)
    assert user is not None
    assert user.username == username
    
    # Test failed authentication
    assert authenticate_user(username, "wrongpass") is None
    assert authenticate_user("nonexistent", password) is None
    
    # Test disabled user
    update_user(username, disabled=True)
    assert authenticate_user(username, password) is None

@pytest.mark.asyncio
async def test_get_current_user(test_user: str, test_token: str):
    """Test current user retrieval from token."""
    # Test valid token
    user = await get_current_user(test_token)
    assert user.username == test_user.username
    assert user.role == test_user.role
    
    # Test expired token
    expired_token = create_access_token(
        {"sub": test_user.username, "role": test_user.role.value},
        expires_delta=timedelta(minutes=-1)
    )
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(expired_token)
    assert exc_info.value.status_code == 401
    
    # Test invalid token
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user("invalid_token")
    assert exc_info.value.status_code == 401

def test_delete_user(clear_users):
    """Test user deletion."""
    # Create users to test with
    admin = create_user("admin_user", "adminpass", role=UserRole.ADMIN)
    user1 = create_user("user1", "userpass")
    user2 = create_user("user2", "userpass")
    
    # Test successful deletion by admin
    assert delete_user(user1.username, admin.username)
    assert get_user(user1.username) is None
    
    # Test deletion of non-existent user
    assert not delete_user("nonexistent", admin.username)
    
    # Test self-deletion prevention
    with pytest.raises(ValueError):
        delete_user(admin.username, admin.username)
    
    # Test deleting last admin prevention
    # Create another admin first
    other_admin = create_user("other_admin", "adminpass", role=UserRole.ADMIN)
    assert delete_user(other_admin.username, admin.username)  # Should succeed
    
    # Now trying to delete the last admin should fail
    with pytest.raises(ValueError, match="Cannot delete the last admin user"):
        delete_user(admin.username, user2.username)

def test_update_user(clear_users):
    """Test user updates."""
    username = "updateuser"
    password = "updatepass123"
    
    # Create test user
    user = create_user(username, password)
    
    # Test email update
    updated = update_user(username, email="test@example.com")
    assert updated is not None
    assert updated.email == "test@example.com"
    
    # Test role update
    updated = update_user(username, role=UserRole.ADMIN)
    assert updated is not None
    assert updated.role == UserRole.ADMIN
    
    # Test disabling user
    updated = update_user(username, disabled=True)
    assert updated is not None
    assert updated.disabled
    
    # Test password update
    new_password = "newpass123"
    updated = update_user(username, password=new_password)
    assert updated is not None
    stored_user = get_user(username)
    assert verify_password(new_password, stored_user.hashed_password)
    
    # Test updating non-existent user
    assert update_user("nonexistent", email="test@example.com") is None

@pytest.mark.asyncio
async def test_validate_admin(clear_users):
    """Test admin validation."""
    # Create test users
    admin = create_user("test_admin", "adminpass", role=UserRole.ADMIN)
    user = create_user("test_user", "userpass")
    
    # Create tokens
    admin_token = create_access_token({"sub": admin.username, "role": UserRole.ADMIN.value})
    user_token = create_access_token({"sub": user.username, "role": UserRole.USER.value})
    
    # Test valid admin
    admin_user = await get_current_user(admin_token)
    await validate_admin(admin_user)
    
    # Test non-admin user
    normal_user = await get_current_user(user_token)
    with pytest.raises(HTTPException) as exc_info:
        await validate_admin(normal_user)
    assert exc_info.value.status_code == 403

def test_list_users(clear_users):
    """Test user listing."""
    # Create test users
    admin = create_user("list_admin", "adminpass", role=UserRole.ADMIN)
    user1 = create_user("list_user1", "userpass")
    user2 = create_user("list_user2", "userpass")
    
    # List all users
    users = list_users()
    assert len(users) == 4  # Including default admin
    usernames = {user.username for user in users}
    assert usernames == {"admin", "list_admin", "list_user1", "list_user2"}

def test_create_access_token():
    """Test JWT token creation."""
    # Test normal token creation
    data = {"sub": "testuser", "role": UserRole.USER.value}
    token = create_access_token(data)
    
    assert token
    assert isinstance(token, str)
    
    # Test custom expiration
    token = create_access_token(data, expires_delta=timedelta(minutes=5))
    assert token
    assert isinstance(token, str)
