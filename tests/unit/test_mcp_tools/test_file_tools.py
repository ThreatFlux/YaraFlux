"""Tests for file tools."""
import json
import uuid
import base64
import hashlib
from io import BytesIO
from unittest.mock import Mock, patch, MagicMock

import pytest

from yaraflux_mcp_server.mcp_tools.file_tools import (
    upload_file,
    get_file_info,
    list_files,
    delete_file,
    download_file,
    extract_strings,
    get_hex_view
)


@patch('yaraflux_mcp_server.mcp_tools.file_tools.get_storage_client')
def test_upload_file_base64(mock_get_storage):
    """Test upload_file with base64 encoding."""
    # Setup mock storage client
    mock_storage = Mock()
    file_id = str(uuid.uuid4())
    file_size = 13  # Length of "Hello, World!"
    file_hash = hashlib.sha256(b"Hello, World!").hexdigest()
    
    # Mock the save_file method to store the args for later inspection
    file_data = None
    metadata_arg = None
    
    def mock_save_file(file_name, data, metadata=None):
        nonlocal file_data, metadata_arg
        file_data = data
        metadata_arg = metadata
        return {
            "file_id": file_id,
            "file_name": "test.txt",
            "file_size": file_size,
            "file_hash": file_hash,
            "mime_type": "text/plain",
            "uploaded_at": "2025-03-09T07:00:00Z"
        }
    
    mock_storage.save_file = mock_save_file
    mock_get_storage.return_value = mock_storage
    
    # Test data
    file_content = b"Hello, World!"
    test_data = base64.b64encode(file_content).decode('utf-8')
    
    # Call the function
    result = upload_file(
        data=test_data,
        file_name="test.txt",
        encoding="base64",
        metadata={"description": "Test file"}
    )
    
    # Verify the result
    assert isinstance(result, dict)
    assert "success" in result
    assert result["success"] is True
    assert "file_info" in result
    assert result["file_info"]["file_id"] == file_id
    assert result["file_info"]["file_size"] == file_size
    assert result["file_info"]["file_hash"] == file_hash
    
    # Verify the file data was properly decoded
    assert file_data == file_content
    
    # Verify the metadata was passed correctly
    assert metadata_arg is not None
    assert "description" in metadata_arg
    assert metadata_arg["description"] == "Test file"


@patch('yaraflux_mcp_server.mcp_tools.file_tools.get_storage_client')
def test_upload_file_text(mock_get_storage):
    """Test upload_file with text encoding."""
    # Setup mock storage client
    mock_storage = Mock()
    file_id = str(uuid.uuid4())
    test_data = "This is plain text content"
    file_size = len(test_data.encode('utf-8'))
    file_hash = hashlib.sha256(test_data.encode('utf-8')).hexdigest()
    
    # Mock the save_file method to store the args for later inspection
    file_data = None
    
    def mock_save_file(file_name, data, metadata=None):
        nonlocal file_data
        file_data = data
        return {
            "file_id": file_id,
            "file_name": "text.txt",
            "file_size": file_size,
            "file_hash": file_hash,
            "mime_type": "text/plain",
            "uploaded_at": "2025-03-09T07:00:00Z"
        }
    
    mock_storage.save_file = mock_save_file
    mock_get_storage.return_value = mock_storage
    
    # Call the function
    result = upload_file(
        data=test_data,
        file_name="text.txt",
        encoding="text"
    )
    
    # Verify the result
    assert isinstance(result, dict)
    assert "success" in result
    assert result["success"] is True
    assert "file_info" in result
    assert result["file_info"]["file_id"] == file_id
    assert result["file_info"]["file_size"] == file_size
    assert result["file_info"]["file_hash"] == file_hash
    
    # Verify the file data was properly encoded
    assert file_data == test_data.encode('utf-8')


@patch('yaraflux_mcp_server.mcp_tools.file_tools.get_storage_client')
def test_get_file_info(mock_get_storage):
    """Test get_file_info tool."""
    # Setup mock storage client
    mock_storage = Mock()
    file_id = str(uuid.uuid4())
    mock_storage.get_file_info.return_value = {
        "file_id": file_id,
        "file_name": "test.txt",
        "file_size": 1024,
        "file_hash": "abc123",
        "mime_type": "text/plain",
        "uploaded_at": "2025-03-09T07:00:00Z",
        "custom_field": "custom value"
    }
    mock_get_storage.return_value = mock_storage
    
    # Call the function
    result = get_file_info(file_id=file_id)
    
    # Verify the result
    assert isinstance(result, dict)
    assert result["success"] is True
    assert "file_info" in result
    assert result["file_info"]["file_name"] == "test.txt"
    assert result["file_info"]["file_size"] == 1024
    assert result["file_info"]["custom_field"] == "custom value"
    
    # Verify the storage client was called correctly
    mock_storage.get_file_info.assert_called_once_with(file_id)


@patch('yaraflux_mcp_server.mcp_tools.file_tools.get_storage_client')
def test_get_file_info_not_found(mock_get_storage):
    """Test get_file_info with nonexistent file."""
    # Setup mock storage client to raise an exception
    mock_storage = Mock()
    mock_storage.get_file_info.side_effect = Exception("File not found")
    mock_get_storage.return_value = mock_storage
    
    # Call the function
    result = get_file_info(file_id="nonexistent")
    
    # Verify the result
    assert isinstance(result, dict)
    assert result["success"] is False
    assert "message" in result
    assert "File not found" in result["message"]


@patch('yaraflux_mcp_server.mcp_tools.file_tools.get_storage_client')
def test_list_files(mock_get_storage):
    """Test list_files tool."""
    # Setup mock storage client
    mock_storage = Mock()
    file1_id = str(uuid.uuid4())
    file2_id = str(uuid.uuid4())
    
    mock_storage.list_files.return_value = {
        "files": [
            {
                "file_id": file1_id,
                "file_name": "file1.txt",
                "file_size": 1024,
                "uploaded_at": "2025-03-09T07:00:00Z"
            },
            {
                "file_id": file2_id,
                "file_name": "file2.bin",
                "file_size": 2048,
                "uploaded_at": "2025-03-09T08:00:00Z"
            }
        ],
        "total": 2,
        "page": 1,
        "page_size": 100
    }
    mock_get_storage.return_value = mock_storage
    
    # Call the function
    result = list_files(page=1, page_size=100, sort_by="uploaded_at")
    
    # Verify the result
    assert isinstance(result, dict)
    assert result["success"] is True
    assert "files" in result
    assert len(result["files"]) == 2
    assert "total" in result
    assert result["total"] == 2
    assert "page" in result
    assert result["page"] == 1
    
    # Verify the storage client was called correctly
    mock_storage.list_files.assert_called_once_with(1, 100, "uploaded_at", True)


@patch('yaraflux_mcp_server.mcp_tools.file_tools.get_storage_client')
def test_delete_file(mock_get_storage):
    """Test delete_file tool."""
    # Setup mock storage client
    mock_storage = Mock()
    file_id = "test-file-id"
    mock_storage.get_file_info.return_value = {
        "file_id": file_id,
        "file_name": "test.txt"
    }
    mock_storage.delete_file.return_value = True
    mock_get_storage.return_value = mock_storage
    
    # Call the function
    result = delete_file(file_id=file_id)
    
    # Verify the result
    assert isinstance(result, dict)
    assert result["success"] is True
    assert "file_id" in result
    assert result["file_id"] == file_id
    
    # Verify the storage client was called correctly
    mock_storage.delete_file.assert_called_once_with(file_id)


@patch('yaraflux_mcp_server.mcp_tools.file_tools.get_storage_client')
def test_delete_file_not_found(mock_get_storage):
    """Test delete_file with nonexistent file."""
    # Setup mock storage client
    mock_storage = Mock()
    mock_storage.get_file_info.side_effect = Exception("File not found")
    mock_storage.delete_file.return_value = False
    mock_get_storage.return_value = mock_storage
    
    # Call the function
    result = delete_file(file_id="nonexistent")
    
    # Verify the result
    assert isinstance(result, dict)
    assert result["success"] is False
    assert "message" in result
    assert "not found" in result["message"].lower() or "could not be deleted" in result["message"].lower()


@patch('yaraflux_mcp_server.mcp_tools.file_tools.get_storage_client')
def test_extract_strings(mock_get_storage):
    """Test extract_strings tool."""
    # Setup mock storage client
    mock_storage = Mock()
    file_id = str(uuid.uuid4())
    
    mock_storage.extract_strings.return_value = {
        "file_id": file_id,
        "file_name": "test.bin",
        "strings": ["String1", "String2", "LongerString3"],
        "total_strings": 3,
        "min_length": 4,
        "include_unicode": True,
        "include_ascii": True
    }
    mock_get_storage.return_value = mock_storage
    
    # Call the function
    result = extract_strings(
        file_id=file_id,
        min_length=4,
        include_unicode=True,
        include_ascii=True
    )
    
    # Verify the result
    assert isinstance(result, dict)
    assert result["success"] is True
    assert "file_id" in result
    assert result["file_id"] == file_id
    assert "strings" in result
    assert len(result["strings"]) == 3
    assert "total_strings" in result
    assert result["total_strings"] == 3
    
    # Verify the storage client was called correctly
    mock_storage.extract_strings.assert_called_once_with(
        file_id, 4, True, True, None
    )


@patch('yaraflux_mcp_server.mcp_tools.file_tools.get_storage_client')
def test_get_hex_view(mock_get_storage):
    """Test get_hex_view tool."""
    # Setup mock storage client
    mock_storage = Mock()
    file_id = str(uuid.uuid4())
    
    mock_storage.get_hex_view.return_value = {
        "file_id": file_id,
        "file_name": "test.bin",
        "hex_content": "00000000: 48 65 6c 6c 6f 2c 20 57 6f 72 6c 64 21     Hello, World!",
        "offset": 0,
        "length": 13,
        "total_size": 13,
        "bytes_per_line": 16
    }
    mock_get_storage.return_value = mock_storage
    
    # Call the function
    result = get_hex_view(
        file_id=file_id,
        offset=0,
        length=100,
        bytes_per_line=16
    )
    
    # Verify the result
    assert isinstance(result, dict)
    assert result["success"] is True
    assert "file_id" in result
    assert result["file_id"] == file_id
    assert "hex_content" in result
    assert "Hello, World!" in result["hex_content"]
    
    # Verify the storage client was called correctly
    mock_storage.get_hex_view.assert_called_once_with(
        file_id, 0, 100, 16
    )


@patch('yaraflux_mcp_server.mcp_tools.file_tools.get_storage_client')
def test_download_file(mock_get_storage):
    """Test download_file tool."""
    # Setup mock storage client
    mock_storage = Mock()
    file_id = str(uuid.uuid4())
    file_content = b"Hello, World!"
    
    mock_storage.get_file.return_value = file_content
    mock_storage.get_file_info.return_value = {
        "file_id": file_id,
        "file_name": "test.txt",
        "file_size": len(file_content),
        "mime_type": "text/plain"
    }
    mock_get_storage.return_value = mock_storage
    
    # Call the function
    result = download_file(
        file_id=file_id,
        encoding="base64"
    )
    
    # Verify the result
    assert isinstance(result, dict)
    assert result["success"] is True
    assert "file_id" in result
    assert result["file_id"] == file_id
    assert "data" in result
    decoded_data = base64.b64decode(result["data"])
    assert decoded_data == file_content
    assert "encoding" in result
    assert result["encoding"] == "base64"
    
    # Verify the storage client was called correctly
    mock_storage.get_file.assert_called_once_with(file_id)
    mock_storage.get_file_info.assert_called_once_with(file_id)


@patch('yaraflux_mcp_server.mcp_tools.file_tools.get_storage_client')
def test_download_file_text(mock_get_storage):
    """Test download_file with text encoding."""
    # Setup mock storage client
    mock_storage = Mock()
    file_id = str(uuid.uuid4())
    file_content = b"Hello, World!"
    
    mock_storage.get_file.return_value = file_content
    mock_storage.get_file_info.return_value = {
        "file_id": file_id,
        "file_name": "test.txt",
        "file_size": len(file_content),
        "mime_type": "text/plain"
    }
    mock_get_storage.return_value = mock_storage
    
    # Call the function
    result = download_file(
        file_id=file_id,
        encoding="text"
    )
    
    # Verify the result
    assert isinstance(result, dict)
    assert result["success"] is True
    assert "file_id" in result
    assert result["file_id"] == file_id
    assert "data" in result
    assert result["data"] == "Hello, World!"
    assert "encoding" in result
    assert result["encoding"] == "text"
