"""Tests for the MCP tools module."""

import base64
import time
from datetime import datetime, UTC
from unittest.mock import MagicMock, patch

import pytest

from yaraflux_mcp_server.mcp_tools import (
    add_yara_rule,
    delete_yara_rule,
    get_scan_result,
    get_yara_rule,
    list_yara_rules,
    scan_data,
    scan_url,
    update_yara_rule,
    validate_yara_rule,
)
from yaraflux_mcp_server.models import YaraMatch, YaraRuleMetadata, YaraScanResult
from yaraflux_mcp_server.storage import StorageError
from yaraflux_mcp_server.yara_service import YaraError

def test_list_yara_rules(mock_storage: MagicMock):
    """Test listing YARA rules via MCP tool."""
    now = datetime.now(UTC)
    mock_rules = [
        YaraRuleMetadata(
            name="rule1.yar",
            source="custom",
            created=now,
            is_compiled=True
        ),
        YaraRuleMetadata(
            name="rule2.yar",
            source="community",
            created=now,
            is_compiled=True
        ),
    ]
    
    with patch("yaraflux_mcp_server.yara_service.yara_service.list_rules") as mock_list:
        mock_list.return_value = mock_rules
        
        # Test listing all rules
        result = list_yara_rules()
        assert len(result) == 2
        assert result[0]["name"] == "rule1.yar"
        assert result[1]["name"] == "rule2.yar"
        
        # Test filtering by source
        mock_list.return_value = [mock_rules[0]]
        result = list_yara_rules(source="custom")
        assert len(result) == 1
        assert result[0]["name"] == "rule1.yar"
        
        # Test error handling
        mock_list.side_effect = YaraError("Test error")
        result = list_yara_rules()
        assert "error" in result
        assert result["error"] == "Failed to list rules"
        assert "Test error" in result["message"]

def test_get_yara_rule(mock_storage: MagicMock, test_yara_rule: str):
    """Test getting a YARA rule via MCP tool."""
    rule_name = "test_rule.yar"
    
    with patch("yaraflux_mcp_server.yara_service.yara_service.get_rule") as mock_get:
        mock_get.return_value = test_yara_rule
        
        # Test successful retrieval
        result = get_yara_rule(rule_name)
        assert result["name"] == rule_name
        assert result["content"] == test_yara_rule
        assert "metadata" in result
        
        # Test error handling
        mock_get.side_effect = YaraError("Test error")
        result = get_yara_rule("nonexistent.yar")
        assert "error" in result

def test_validate_yara_rule(test_yara_rule: str):
    """Test YARA rule validation via MCP tool."""
    # Test valid rule
    with patch("yara.compile") as mock_compile:
        mock_rules = MagicMock()
        mock_compile.return_value = mock_rules
        
        result = validate_yara_rule(test_yara_rule)
        assert result["valid"]
        assert "message" in result
    
    # Test invalid rule
    with patch("yara.compile") as mock_compile:
        mock_compile.side_effect = Exception("Invalid syntax")
        try:
            result = validate_yara_rule("invalid rule content")
            assert not result["valid"]
            assert "Invalid syntax" in result["message"]
        except Exception as e:
            pytest.fail(f"Unexpected error: {str(e)}")

def test_add_yara_rule(mock_storage: MagicMock, test_yara_rule: str):
    """Test adding a YARA rule via MCP tool."""
    rule_name = "add_test.yar"
    
    with patch("yaraflux_mcp_server.yara_service.yara_service.add_rule") as mock_add:
        mock_add.return_value = YaraRuleMetadata(
            name=rule_name,
            source="custom",
            created=datetime.now(UTC),
            is_compiled=True
        )
        
        # Test successful addition
        result = add_yara_rule(rule_name, test_yara_rule)
        assert result["success"]
        assert result["metadata"]["name"] == rule_name
        
        # Test error handling
        mock_add.side_effect = YaraError("Test error")
        result = add_yara_rule("invalid.yar", "invalid content")
        assert not result["success"]
        assert "message" in result

def test_update_yara_rule(mock_storage: MagicMock, test_yara_rule: str):
    """Test updating a YARA rule via MCP tool."""
    rule_name = "update_test.yar"
    
    with patch("yaraflux_mcp_server.yara_service.yara_service.update_rule") as mock_update:
        mock_update.return_value = YaraRuleMetadata(
            name=rule_name,
            source="custom",
            created=datetime.now(UTC),
            modified=datetime.now(UTC),
            is_compiled=True
        )
        
        # Test successful update
        result = update_yara_rule(rule_name, test_yara_rule)
        assert result["success"]
        assert result["metadata"]["name"] == rule_name
        
        # Test error handling
        mock_update.side_effect = YaraError("Test error")
        result = update_yara_rule("nonexistent.yar", test_yara_rule)
        assert not result["success"]
        assert "message" in result

def test_delete_yara_rule(mock_storage: MagicMock):
    """Test deleting a YARA rule via MCP tool."""
    rule_name = "delete_test.yar"
    
    with patch("yaraflux_mcp_server.yara_service.yara_service.delete_rule") as mock_delete:
        # Test successful deletion
        mock_delete.return_value = True
        result = delete_yara_rule(rule_name)
        assert result["success"]
        
        # Test deletion of non-existent rule
        mock_delete.return_value = False
        result = delete_yara_rule("nonexistent.yar")
        assert not result["success"]
        
        # Test error handling
        mock_delete.side_effect = YaraError("Test error")
        result = delete_yara_rule(rule_name)
        assert not result["success"]
        assert "message" in result

def test_scan_url(mock_storage: MagicMock):
    """Test URL scanning via MCP tool."""
    test_url = "http://example.com/test.txt"
    
    # Create mock scan result
    scan_result = YaraScanResult(
        file_name="test.txt",
        file_size=100,
        file_hash="abcdef",
        scan_time=0.1,
        matches=[
            YaraMatch(
                rule="test_rule",
                namespace="default",
                strings=[{"offset": 0, "name": "$test", "data": b"test string"}]
            )
        ]
    )
    
    with patch("yaraflux_mcp_server.yara_service.yara_service.fetch_and_scan") as mock_scan:
        mock_scan.return_value = scan_result
        
        # Test successful scan
        result = scan_url(test_url)
        assert result["success"]
        assert result["file_name"] == "test.txt"
        assert len(result["matches"]) == 1
        assert result["match_count"] == 1
        
        # Test error handling
        mock_scan.side_effect = YaraError("Test error")
        result = scan_url(test_url)
        assert not result["success"]
        assert "message" in result

def test_scan_data(mock_storage: MagicMock):
    """Test data scanning via MCP tool."""
    test_data = base64.b64encode(b"test data").decode()
    filename = "test.txt"
    
    # Create mock scan result
    scan_result = YaraScanResult(
        file_name=filename,
        file_size=len(b"test data"),
        file_hash="abcdef",
        scan_time=0.1,
        matches=[
            YaraMatch(
                rule="test_rule",
                namespace="default",
                strings=[{"offset": 0, "name": "$test", "data": b"test data"}]
            )
        ]
    )
    
    with patch("yaraflux_mcp_server.yara_service.yara_service.match_data") as mock_scan:
        mock_scan.return_value = scan_result
        
        # Test base64 encoded data
        result = scan_data(test_data, filename)
        assert result["success"]
        assert result["file_name"] == filename
        assert "scan_id" in result
        
        # Test text data
        result = scan_data("test data", filename, encoding="text")
        assert result["success"]
        assert result["file_name"] == filename
        
        # Test invalid encoding
        result = scan_data(test_data, filename, encoding="invalid")
        assert not result["success"]
        assert "message" in result
        assert "Unsupported encoding" in result["message"]
        
        # Test error handling
        mock_scan.side_effect = YaraError("Test error")
        result = scan_data(test_data, filename)
        assert not result["success"]
        assert "message" in result

def test_get_scan_result(mock_storage: MagicMock):
    """Test retrieving scan results via MCP tool."""
    scan_id = "test-scan-id"
    mock_result = {
        "scan_id": scan_id,
        "file_name": "test.txt",
        "matches": [{"rule": "test_rule"}],
        "scan_time": time.time(),
        "match_count": 1
    }
    
    with patch("yaraflux_mcp_server.storage.get_storage_client") as mock_get_storage:
        mock_get_storage.return_value = mock_storage
        mock_storage.get_result.return_value = mock_result
        
        # Test successful retrieval
        result = get_scan_result(scan_id)
        assert result["success"]
        assert result["result"] == mock_result
        
        # Test error handling
        mock_storage.get_result.side_effect = StorageError("Test error")
        result = get_scan_result(scan_id)
        assert not result["success"]
        assert "message" in result
