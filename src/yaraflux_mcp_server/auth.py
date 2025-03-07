"""Authentication and authorization module for YaraFlux MCP Server.

This module provides JWT-based authentication and authorization functionality,
including user management, token generation, validation, and dependencies for
securing FastAPI routes.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Union

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import ValidationError

from yaraflux_mcp_server.config import settings
from yaraflux_mcp_server.models import TokenData, User, UserInDB, UserRole

# Configure logging
logger = logging.getLogger(__name__)

# Configure password hashing with fallback mechanisms
try:
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    logger.info("Successfully initialized bcrypt password hashing")
except Exception as e:
    logger.error(f"Error initializing bcrypt: {str(e)}")
    # Fallback to basic schemes if bcrypt fails
    try:
        pwd_context = CryptContext(schemes=["sha256_crypt"], deprecated="auto")
        logger.warning(
            "Using fallback password hashing (sha256_crypt) due to bcrypt initialization failure"
        )
    except Exception as e:
        logger.critical(f"Critical error initializing password hashing: {str(e)}")
        raise RuntimeError("Failed to initialize password hashing system")

# OAuth2 scheme for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_PREFIX}/auth/token")

# Mock user database - in a real application, replace with a database
# For simplicity, we'll use a dictionary in memory
_user_db: Dict[str, UserInDB] = {}


def init_user_db() -> None:
    """Initialize the user database with the admin user."""
    # Admin user is always created
    if settings.ADMIN_USERNAME not in _user_db:
        create_user(
            username=settings.ADMIN_USERNAME, password=settings.ADMIN_PASSWORD, role=UserRole.ADMIN
        )
        logger.info(f"Created admin user: {settings.ADMIN_USERNAME}")


def get_password_hash(password: str) -> str:
    """Generate a hashed password.

    Args:
        password: Plain text password

    Returns:
        Hashed password
    """
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against a hash.

    Args:
        plain_password: Plain text password
        hashed_password: Hashed password

    Returns:
        True if password matches, False otherwise
    """
    return pwd_context.verify(plain_password, hashed_password)


def get_user(username: str) -> Optional[UserInDB]:
    """Get a user from the database by username.

    Args:
        username: Username to look up

    Returns:
        User object if found, None otherwise
    """
    return _user_db.get(username)


def create_user(
    username: str, password: str, role: UserRole = UserRole.USER, email: Optional[str] = None
) -> User:
    """Create a new user.

    Args:
        username: Username for the new user
        password: Plain text password
        role: User role (default: USER)
        email: Optional email address

    Returns:
        Created user object

    Raises:
        ValueError: If username already exists
    """
    if username in _user_db:
        raise ValueError(f"User already exists: {username}")

    hashed_password = get_password_hash(password)
    user = UserInDB(username=username, hashed_password=hashed_password, role=role, email=email)
    _user_db[username] = user
    logger.info(f"Created user: {username} with role {role}")

    # Return a User object (without the hashed password)
    return User(username=user.username, role=user.role, email=user.email, disabled=user.disabled)


def authenticate_user(username: str, password: str) -> Optional[UserInDB]:
    """Authenticate a user with username and password.

    Args:
        username: Username
        password: Plain text password

    Returns:
        User object if authentication succeeds, None otherwise
    """
    user = get_user(username)
    if not user:
        logger.warning(f"Authentication failed: User not found: {username}")
        return None
    if not verify_password(password, user.hashed_password):
        logger.warning(f"Authentication failed: Invalid password for user: {username}")
        return None
    if user.disabled:
        logger.warning(f"Authentication failed: User is disabled: {username}")
        return None
    return user


def create_access_token(
    data: Dict[str, Union[str, datetime]], expires_delta: Optional[timedelta] = None
) -> str:
    """Create a JWT access token.

    Args:
        data: Data to encode in the token
        expires_delta: Optional expiration time delta

    Returns:
        JWT token string
    """
    to_encode = data.copy()

    # Set expiration time
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire})

    # Create the JWT token
    token = jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

    return token


async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    """Get the current user from a JWT token.

    Args:
        token: JWT token

    Returns:
        User object

    Raises:
        HTTPException: If token is invalid or user not found
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        # Decode the JWT token
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])

        # Extract username and role from token
        username: str = payload.get("sub")
        role: str = payload.get("role")

        if username is None:
            logger.warning("Invalid token: Missing username")
            raise credentials_exception

        # Create token data object
        token_data = TokenData(username=username, role=UserRole(role) if role else UserRole.USER)
    except (JWTError, ValidationError) as e:
        logger.warning(f"Token validation error: {str(e)}")
        raise credentials_exception

    # Get the user from the database
    user = get_user(token_data.username)
    if user is None:
        logger.warning(f"User from token not found: {token_data.username}")
        raise credentials_exception
    if user.disabled:
        logger.warning(f"User from token is disabled: {token_data.username}")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Inactive user")

    # Convert UserInDB to User (remove hashed_password)
    return User(username=user.username, role=user.role, email=user.email, disabled=user.disabled)


async def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    """Get the current active user.

    Args:
        current_user: User from token

    Returns:
        User object

    Raises:
        HTTPException: If user is disabled
    """
    if current_user.disabled:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Inactive user")
    return current_user


async def validate_admin(current_user: User = Depends(get_current_active_user)) -> User:
    """Validate that the current user is an admin.

    Args:
        current_user: User from token

    Returns:
        User object

    Raises:
        HTTPException: If user is not an admin
    """
    if current_user.role != UserRole.ADMIN:
        logger.warning(f"Admin access denied for user: {current_user.username}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required"
        )
    return current_user


def delete_user(username: str, current_username: str) -> bool:
    """Delete a user from the database.

    Args:
        username: Username to delete
        current_username: Username of the user performing the deletion

    Returns:
        True if user was deleted, False if not found

    Raises:
        ValueError: If attempting to delete the last admin user or self
    """
    if username not in _user_db:
        return False

    # Prevent deleting self
    if username == current_username:
        raise ValueError("Cannot delete your own account")

    # Prevent deleting the last admin
    user = _user_db[username]
    if user.role == UserRole.ADMIN:
        # Count remaining admins
        admin_count = sum(1 for u in _user_db.values() if u.role == UserRole.ADMIN)
        if admin_count <= 1:
            raise ValueError("Cannot delete the last admin user")

    # Delete the user
    del _user_db[username]
    logger.info(f"Deleted user: {username}")
    return True


def list_users() -> List[User]:
    """List all users in the database.

    Returns:
        List of User objects (without hashed passwords)
    """
    return [
        User(username=user.username, role=user.role, email=user.email, disabled=user.disabled)
        for user in _user_db.values()
    ]


def update_user(
    username: str,
    role: Optional[UserRole] = None,
    email: Optional[str] = None,
    disabled: Optional[bool] = None,
    password: Optional[str] = None,
) -> Optional[User]:
    """Update a user in the database.

    Args:
        username: Username to update
        role: New role (if provided)
        email: New email (if provided)
        disabled: New disabled status (if provided)
        password: New password (if provided)

    Returns:
        Updated User object if found, None otherwise

    Raises:
        ValueError: If attempting to update the last admin user's role
    """
    user = _user_db.get(username)
    if not user:
        return None

    # Handle role change for admin
    if role is not None and user.role == UserRole.ADMIN and role != UserRole.ADMIN:
        # Count remaining admins
        admin_count = sum(1 for u in _user_db.values() if u.role == UserRole.ADMIN)
        if admin_count <= 1:
            raise ValueError("Cannot change role of the last admin user")
        user.role = role
    elif role is not None:
        user.role = role

    # Update other fields if provided
    if email is not None:
        user.email = email
    if disabled is not None:
        user.disabled = disabled
    if password is not None:
        user.hashed_password = get_password_hash(password)

    logger.info(f"Updated user: {username}")

    # Return a User object (without the hashed password)
    return User(username=user.username, role=user.role, email=user.email, disabled=user.disabled)
