"""Tests for the YARA service module."""

import hashlib
import os
from datetime import datetime, UTC
from io import BytesIO
from typing import Dict, Generator
from unittest.mock import MagicMock, patch

import pytest
import yara

from yaraflux_mcp_server.models import YaraMatch, YaraRuleMetadata, YaraScanResult
from yaraflux_mcp_server.storage import StorageError
from yaraflux_mcp_server.yara_service import YaraError, YaraService, yara_service

def test_add_rule(setup_mock_storage: MagicMock, test_yara_rule: str):
    """Test adding a YARA rule."""
    rule_name = "test_rule.yar"
    
    # Mock rule compilation
    with patch("yara.compile") as mock_compile:
        mock_rules = MagicMock(spec=yara.Rules)
        mock_compile.return_value = mock_rules
        
        # Test successful rule addition
        metadata = yara_service.add_rule(rule_name, test_yara_rule)
        assert metadata is not None
        assert metadata.name == rule_name
        assert metadata.is_compiled
        
        # Verify storage was called
        setup_mock_storage.save_rule.assert_called_once_with(rule_name, test_yara_rule, "custom")
        
        # Test invalid rule content
        mock_compile.side_effect = yara.Error("Invalid syntax")
        with pytest.raises(YaraError):
            yara_service.add_rule("invalid.yar", "invalid rule content")

def test_update_rule(setup_mock_storage: MagicMock, test_yara_rule: str):
    """Test updating a YARA rule."""
    rule_name = "test_rule.yar"
    
    # Mock rule compilation
    with patch("yara.compile") as mock_compile:
        mock_rules = MagicMock(spec=yara.Rules)
        mock_compile.return_value = mock_rules
        
        # Test successful update
        metadata = yara_service.update_rule(rule_name, test_yara_rule)
        assert metadata is not None
        assert metadata.name == rule_name
        assert metadata.is_compiled
        
        # Test updating non-existent rule
        setup_mock_storage.get_rule.side_effect = StorageError("Rule not found")
        with pytest.raises(YaraError):
            yara_service.update_rule("nonexistent.yar", test_yara_rule)

def test_delete_rule(setup_mock_storage: MagicMock):
    """Test deleting a YARA rule."""
    rule_name = "test_rule.yar"
    
    # Test successful deletion
    setup_mock_storage.delete_rule.return_value = True
    assert yara_service.delete_rule(rule_name)
    setup_mock_storage.delete_rule.assert_called_once_with(rule_name, "custom")
    
    # Test deletion failure
    setup_mock_storage.delete_rule.return_value = False
    assert not yara_service.delete_rule("nonexistent.yar")

def test_get_rule(setup_mock_storage: MagicMock, test_yara_rule: str):
    """Test getting a YARA rule."""
    rule_name = "test_rule.yar"
    
    # Test successful retrieval
    setup_mock_storage.get_rule.return_value = test_yara_rule
    content = yara_service.get_rule(rule_name)
    assert content == test_yara_rule
    setup_mock_storage.get_rule.assert_called_with(rule_name, "custom")
    
    # Test retrieval failure
    setup_mock_storage.get_rule.side_effect = StorageError("Rule not found")
    with pytest.raises(YaraError):
        yara_service.get_rule("nonexistent.yar")

def test_list_rules(setup_mock_storage: MagicMock):
    """Test listing YARA rules."""
    # Test listing all rules
    rules = yara_service.list_rules()
    assert len(rules) == 1
    assert rules[0].name == "test_rule.yar"
    assert rules[0].source == "custom"
    
    # Test filtering by source
    setup_mock_storage.list_rules.return_value = []
    rules = yara_service.list_rules("community")
    assert len(rules) == 0

def test_match_file(setup_mock_storage: MagicMock, test_yara_rule: str, temp_dir: str):
    """Test matching YARA rules against a file."""
    # Create test file
    test_file = os.path.join(temp_dir, "test_file.txt")
    test_content = b"test string"
    with open(test_file, "wb") as f:
        f.write(test_content)
    
    # Mock rule compilation and matching
    with patch("yara.compile") as mock_compile:
        mock_rules = MagicMock()
        mock_match = MagicMock()
        mock_match.rule = "test_rule"
        mock_match.namespace = "default"
        mock_match.meta = {}
        mock_match.strings = [(0, "$test", b"test string")]
        mock_rules.match.return_value = [mock_match]
        mock_compile.return_value = mock_rules
        
        # Test successful match
        result = yara_service.match_file(test_file)
        assert result is not None
        assert result.file_name == "test_file.txt"
        assert result.file_size == len(test_content)
        assert result.file_hash == hashlib.sha256(test_content).hexdigest()
        assert len(result.matches) == 1
        assert result.matches[0].rule == "test_rule"
        
        # Test file size limit
        large_content = b"x" * (yara_service.settings.YARA_MAX_FILE_SIZE + 1)
        large_file = os.path.join(temp_dir, "large_file.txt")
        with open(large_file, "wb") as f:
            f.write(large_content)
        
        with pytest.raises(YaraError):
            yara_service.match_file(large_file)

def test_match_data(setup_mock_storage: MagicMock, test_yara_rule: str):
    """Test matching YARA rules against in-memory data."""
    # Setup test data
    test_data = b"test string"
    test_filename = "memory_test.txt"
    
    # Mock rule compilation and matching
    with patch("yara.compile") as mock_compile:
        mock_rules = MagicMock()
        mock_match = MagicMock()
        mock_match.rule = "test_rule"
        mock_match.namespace = "default"
        mock_match.meta = {}
        mock_match.strings = [(0, "$test", b"test string")]
        mock_rules.match.return_value = [mock_match]
        mock_compile.return_value = mock_rules
        
        # Test successful match with bytes
        result = yara_service.match_data(test_data, test_filename)
        assert result is not None
        assert result.file_name == test_filename
        assert result.file_size == len(test_data)
        assert result.file_hash == hashlib.sha256(test_data).hexdigest()
        assert len(result.matches) == 1
        assert result.matches[0].rule == "test_rule"
        
        # Test successful match with BytesIO
        data_io = BytesIO(test_data)
        result = yara_service.match_data(data_io, test_filename)
        assert result is not None
        assert len(result.matches) == 1
        
        # Test data size limit
        large_data = b"x" * (yara_service.settings.YARA_MAX_FILE_SIZE + 1)
        with pytest.raises(YaraError):
            yara_service.match_data(large_data, "large_test.txt")

def test_rule_compilation(setup_mock_storage: MagicMock, test_yara_rule: str):
    """Test YARA rule compilation."""
    rule_name = "test_rule.yar"
    
    # Mock rule retrieval and compilation
    setup_mock_storage.get_rule.return_value = test_yara_rule
    
    with patch("yara.compile") as mock_compile:
        mock_rules = MagicMock(spec=yara.Rules)
        mock_compile.return_value = mock_rules
        
        # Test successful compilation
        compiled_rule = yara_service._compile_rule(rule_name)
        assert isinstance(compiled_rule, yara.Rules)
        
        # Test compilation error
        mock_compile.side_effect = yara.Error("Test error")
        with pytest.raises(YaraError):
            yara_service._compile_rule("invalid.yar")

def test_rule_includes(setup_mock_storage: MagicMock):
    """Test YARA rule includes handling."""
    # Setup main rule with include
    main_rule = """
    include "included.yar"
    rule main_rule {
        condition:
            included_rule
    }
    """
    
    # Setup included rule
    included_rule = """
    rule included_rule {
        condition:
            true
    }
    """
    
    def get_rule_mock(name: str, source: str = "custom") -> str:
        if name == "main.yar":
            return main_rule
        elif name == "included.yar":
            return included_rule
        raise StorageError(f"Rule not found: {name}")
    
    # Set up mock storage
    setup_mock_storage.get_rule.side_effect = get_rule_mock
    
    # Mock yara.compile
    with patch("yara.compile") as mock_compile:
        mock_rules = MagicMock(spec=yara.Rules)
        mock_compile.return_value = mock_rules
        
        # Test successful compilation with include
        compiled_rule = yara_service._compile_rule("main.yar")
        assert isinstance(compiled_rule, yara.Rules)
        
        # Test missing include
        setup_mock_storage.get_rule.side_effect = StorageError("Rule not found")
        with pytest.raises(YaraError):
            yara_service._compile_rule("main.yar")
