"""Tests for MCP tools functionality."""

import pytest
from unittest.mock import patch, MagicMock

from yaraflux_mcp_server.mcp_tools import (
    list_yara_rules,
    get_yara_rule,
    validate_yara_rule
)
from yaraflux_mcp_server.models import YaraRuleMetadata
from yaraflux_mcp_server.yara_service import YaraError
from datetime import datetime


def test_list_yara_rules():
    """Test listing YARA rules via MCP tool."""
    # Create mock rules
    mock_rules = [
        YaraRuleMetadata(
            name="rule1.yar",
            source="custom",
            created=datetime.utcnow(),
            is_compiled=True
        ),
        YaraRuleMetadata(
            name="rule2.yar",
            source="community",
            created=datetime.utcnow(),
            is_compiled=True
        )
    ]
    
    # Mock yara_service.list_rules
    with patch('yaraflux_mcp_server.mcp_tools.yara_service') as mock_service:
        mock_service.list_rules.return_value = mock_rules
        
        # Call the MCP tool
        result = list_yara_rules()
        
        # Check the result
        assert len(result) == 2
        assert result[0]["name"] == "rule1.yar"
        assert result[1]["name"] == "rule2.yar"
        
        # Verify that the method was called
        mock_service.list_rules.assert_called_once_with(None)


def test_get_yara_rule():
    """Test getting a YARA rule via MCP tool."""
    # Mock rule content
    mock_content = "rule TestRule { condition: true }"
    mock_metadata = YaraRuleMetadata(
        name="test_rule.yar",
        source="custom",
        created=datetime.utcnow(),
        is_compiled=True
    )
    
    # Mock yara_service methods
    with patch('yaraflux_mcp_server.mcp_tools.yara_service') as mock_service:
        mock_service.get_rule.return_value = mock_content
        mock_service.list_rules.return_value = [mock_metadata]
        
        # Call the MCP tool
        result = get_yara_rule("test_rule.yar")
        
        # Check the result
        assert result["name"] == "test_rule.yar"
        assert result["content"] == mock_content
        assert "metadata" in result
        
        # Verify that the methods were called
        mock_service.get_rule.assert_called_once_with("test_rule.yar", "custom")
        mock_service.list_rules.assert_called_once_with("custom")


def test_validate_yara_rule_valid():
    """Test validating a valid YARA rule via MCP tool."""
    # Mock valid rule
    valid_rule = "rule TestRule { condition: true }"
    
    # Mock yara_service methods
    with patch('yaraflux_mcp_server.mcp_tools.yara_service') as mock_service:
        # Set up add_rule to succeed, delete_rule to succeed
        mock_service.add_rule.return_value = MagicMock()
        mock_service.delete_rule.return_value = True
        
        # Call the MCP tool
        result = validate_yara_rule(valid_rule)
        
        # Check the result
        assert result["valid"] is True
        assert "message" in result
        
        # Verify that the methods were called
        mock_service.add_rule.assert_called_once()
        mock_service.delete_rule.assert_called_once()


def test_validate_yara_rule_invalid():
    """Test validating an invalid YARA rule via MCP tool."""
    # Mock invalid rule
    invalid_rule = "rule InvalidRule { invalid_syntax }"
    
    # Mock yara_service.add_rule to raise YaraError
    with patch('yaraflux_mcp_server.mcp_tools.yara_service') as mock_service:
        mock_service.add_rule.side_effect = YaraError("Invalid YARA rule")
        
        # Call the MCP tool
        result = validate_yara_rule(invalid_rule)
        
        # Check the result
        assert result["valid"] is False
        assert "message" in result
        assert "Invalid YARA rule" in result["message"]
        
        # Verify that the method was called
        mock_service.add_rule.assert_called_once()
