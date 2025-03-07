"""Pydantic models for YaraFlux MCP Server.

This module defines data models for requests, responses, and internal representations 
used by the YaraFlux MCP Server.
"""

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any, Union
from pydantic import BaseModel, Field, HttpUrl, validator
from uuid import UUID, uuid4


class UserRole(str, Enum):
    """User roles for access control."""
    ADMIN = "admin"
    USER = "user"


class TokenData(BaseModel):
    """Data stored in JWT token."""
    username: str
    role: UserRole
    exp: Optional[datetime] = None


class Token(BaseModel):
    """Authentication token response."""
    access_token: str
    token_type: str = "bearer"


class User(BaseModel):
    """User model for authentication and authorization."""
    username: str
    email: Optional[str] = None
    disabled: bool = False
    role: UserRole = UserRole.USER


class UserInDB(User):
    """User model as stored in database with hashed password."""
    hashed_password: str


class YaraMatch(BaseModel):
    """Model for YARA rule match details."""
    rule: str
    namespace: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    meta: Dict[str, Any] = Field(default_factory=dict)
    strings: List[Dict[str, Any]] = Field(default_factory=list)


class YaraScanResult(BaseModel):
    """Model for YARA scanning results."""
    scan_id: UUID = Field(default_factory=uuid4)
    file_name: str
    file_size: int
    file_hash: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    matches: List[YaraMatch] = Field(default_factory=list)
    scan_time: float  # Scan duration in seconds
    timeout_reached: bool = False
    error: Optional[str] = None


class YaraRuleMetadata(BaseModel):
    """Metadata for a YARA rule."""
    name: str
    source: str  # 'community' or 'custom'
    author: Optional[str] = None
    description: Optional[str] = None
    reference: Optional[str] = None
    created: datetime = Field(default_factory=datetime.utcnow)
    modified: Optional[datetime] = None
    tags: List[str] = Field(default_factory=list)
    is_compiled: bool = False


class YaraRuleContent(BaseModel):
    """Model for YARA rule content."""
    source: str  # The actual rule text


class YaraRule(YaraRuleMetadata):
    """Complete YARA rule with content."""
    content: YaraRuleContent


class YaraRuleCreate(BaseModel):
    """Model for creating a new YARA rule."""
    name: str
    content: str
    author: Optional[str] = None
    description: Optional[str] = None
    reference: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    content_type: Optional[str] = "yara"  # Can be 'yara' or 'json'
    
    @validator('name')
    def name_must_be_valid(cls, v):
        """Validate rule name."""
        if not v or not v.strip():
            raise ValueError('name cannot be empty')
        if '/' in v or '\\' in v:
            raise ValueError('name cannot contain path separators')
        return v


class ScanRequest(BaseModel):
    """Model for file scan request."""
    url: Optional[HttpUrl] = None
    rule_names: Optional[List[str]] = None  # If None, use all available rules
    timeout: Optional[int] = None  # Scan timeout in seconds
    
    @validator('rule_names')
    def validate_rule_names(cls, v):
        """Validate rule names."""
        if v is not None and len(v) == 0:
            return None  # Empty list is treated as None (use all rules)
        return v


class ScanResult(BaseModel):
    """Model for scan result response."""
    result: YaraScanResult


class ErrorResponse(BaseModel):
    """Standard error response."""
    error: str
    detail: Optional[str] = None
