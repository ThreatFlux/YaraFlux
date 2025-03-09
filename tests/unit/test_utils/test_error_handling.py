"""Unit tests for error_handling module."""
import logging
import pytest
from unittest.mock import patch, MagicMock

from yaraflux_mcp_server.utils.error_handling import (
    format_error_message,
    handle_tool_error,
    safe_execute,
)
from yaraflux_mcp_server.yara_service import YaraError


def test_format_error_message_yara_error():
    """Test formatting a YaraError."""
    error = YaraError("Invalid YARA rule syntax")
    message = format_error_message(error)
    assert message == "YARA error: Invalid YARA rule syntax"


def test_format_error_message_value_error():
    """Test formatting a ValueError."""
    error = ValueError("Invalid parameter value")
    message = format_error_message(error)
    assert message == "Invalid parameter: Invalid parameter value"


def test_format_error_message_file_not_found():
    """Test formatting a FileNotFoundError."""
    error = FileNotFoundError("test.yar")
    message = format_error_message(error)
    assert message == "File not found: test.yar"


def test_format_error_message_permission_error():
    """Test formatting a PermissionError."""
    error = PermissionError("Cannot write to file")
    message = format_error_message(error)
    assert message == "Permission denied: Cannot write to file"


def test_format_error_message_generic():
    """Test formatting a generic exception."""
    error = Exception("Something went wrong")
    message = format_error_message(error)
    assert message == "Error: Something went wrong"


@patch("yaraflux_mcp_server.utils.error_handling.logger")
def test_handle_tool_error_basic(mock_logger):
    """Test basic error handling."""
    error = ValueError("Test error")
    result = handle_tool_error("test_function", error)
    
    # Check logger was called
    mock_logger.log.assert_called_once()
    
    # Check return value structure
    assert result["success"] is False
    assert "Invalid parameter: Test error" in result["message"]
    assert result["error_type"] == "ValueError"


@patch("yaraflux_mcp_server.utils.error_handling.logger")
@patch("yaraflux_mcp_server.utils.error_handling.traceback")
def test_handle_tool_error_with_traceback(mock_traceback, mock_logger):
    """Test error handling with traceback inclusion."""
    error = ValueError("Test error")
    mock_traceback.format_exc.return_value = "Traceback:\n  File 'test.py', line 1\n  ValueError: Test error"
    
    result = handle_tool_error("test_function", error, include_traceback=True)
    
    # Verify traceback.format_exc was called
    mock_traceback.format_exc.assert_called_once()
    
    # Verify correct log level and message structure
    log_call = mock_logger.log.call_args
    assert log_call is not None
    assert log_call[0][0] == logging.ERROR  # Check log level
    
    # Check return value
    assert result["success"] is False
    assert "Invalid parameter: Test error" in result["message"]


@patch("yaraflux_mcp_server.utils.error_handling.logger")
def test_handle_tool_error_custom_log_level(mock_logger):
    """Test error handling with custom log level."""
    error = ValueError("Test error")
    result = handle_tool_error("test_function", error, log_level=logging.WARNING)
    
    # Check logger was called with WARNING level
    mock_logger.log.assert_called_once_with(logging.WARNING, "Error in test_function: Invalid parameter: Test error")
    
    # Check return value
    assert result["success"] is False


def test_safe_execute_success():
    """Test successful execution."""
    def test_op(x, y):
        return x + y
    
    result = safe_execute("test_function", test_op, x=1, y=2)
    
    assert result["success"] is True
    assert result["result"] == 3


def test_safe_execute_already_success_dict():
    """Test operation that returns a success dict."""
    def test_op():
        return {"success": True, "data": "test"}
    
    result = safe_execute("test_function", test_op)
    
    assert result["success"] is True
    assert result["data"] == "test"


@patch("yaraflux_mcp_server.utils.error_handling.handle_tool_error")
def test_safe_execute_error(mock_handle_error):
    """Test operation that raises an error."""
    def test_op():
        raise ValueError("Test error")
    
    mock_handle_error.return_value = {"success": False, "message": "Handled error"}
    
    result = safe_execute("test_function", test_op)
    
    mock_handle_error.assert_called_once()
    assert result["success"] is False
    assert result["message"] == "Handled error"


def test_safe_execute_with_custom_handler():
    """Test error handling with custom handlers."""
    def test_op():
        raise ValueError("Test error")
    
    def custom_handler(error):
        return {"success": False, "message": f"Custom handler: {str(error)}"}
    
    error_handlers = {ValueError: custom_handler}
    
    result = safe_execute("test_function", test_op, error_handlers=error_handlers)
    
    assert result["success"] is False
    assert result["message"] == "Custom handler: Test error"


def test_safe_execute_with_multiple_handlers():
    """Test error handling with multiple custom handlers."""
    def test_op():
        raise ValueError("Test error")
    
    def value_handler(error):
        return {"success": False, "message": "Value handler"}
    
    def type_handler(error):
        return {"success": False, "message": "Type handler"}
    
    # Should use the ValueError handler
    error_handlers = {ValueError: value_handler, TypeError: type_handler}
    
    result = safe_execute("test_function", test_op, error_handlers=error_handlers)
    
    assert result["success"] is False
    assert result["message"] == "Value handler"


def test_safe_execute_handler_not_matching():
    """Test error handling when no custom handler matches."""
    def test_op():
        raise ValueError("Test error")
    
    def type_handler(error):
        return {"success": False, "message": "Type handler"}
    
    # Should fall back to default handler
    error_handlers = {TypeError: type_handler}
    
    with patch("yaraflux_mcp_server.utils.error_handling.handle_tool_error") as mock_handle_error:
        mock_handle_error.return_value = {"success": False, "message": "Default handler"}
        result = safe_execute("test_function", test_op, error_handlers=error_handlers)
    
    assert result["success"] is False
    assert result["message"] == "Default handler"
