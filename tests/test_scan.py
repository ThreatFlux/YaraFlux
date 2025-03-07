"""Tests for YARA scanning functionality."""

import base64
import os
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


def test_scan_url(test_client: TestClient, auth_headers, sample_yara_rule, monkeypatch):
    """Test scanning a file from a URL."""
    # Mock the fetch_and_scan method in yara_service to avoid actual HTTP requests
    from yaraflux_mcp_server.models import YaraScanResult
    from yaraflux_mcp_server.yara_service import yara_service
    
    def mock_fetch_and_scan(*args, **kwargs):
        return YaraScanResult(
            file_name="test_file.txt",
            file_size=100,
            file_hash="test_hash",
            scan_time=0.1,
            matches=[]
        )
    
    # Apply the monkeypatch
    monkeypatch.setattr(yara_service, "fetch_and_scan", mock_fetch_and_scan)
    
    # First add a rule
    test_client.post(
        "/api/v1/rules/",
        json={
            "name": "scan_test_rule",
            "content": sample_yara_rule
        },
        headers=auth_headers
    )
    
    # Test the scan endpoint
    response = test_client.post(
        "/api/v1/scan/url",
        json={
            "url": "https://example.com/test_file.txt"
        },
        headers=auth_headers
    )
    
    assert response.status_code == 200
    data = response.json()
    assert "result" in data
    assert data["result"]["file_name"] == "test_file.txt"
    assert "scan_id" in data["result"]


def test_scan_file(test_client: TestClient, auth_headers, sample_yara_rule):
    """Test scanning an uploaded file."""
    # First add a rule
    test_client.post(
        "/api/v1/rules/",
        json={
            "name": "scan_test_rule",
            "content": sample_yara_rule
        },
        headers=auth_headers
    )
    
    # Create a test file with the content that should match the rule
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(b"test string")
        temp_file_path = temp_file.name
    
    try:
        # Test the scan endpoint
        with open(temp_file_path, "rb") as f:
            response = test_client.post(
                "/api/v1/scan/file",
                files={"file": ("test_file.txt", f, "text/plain")},
                headers=auth_headers
            )
        
        assert response.status_code == 200
        data = response.json()
        assert "result" in data
        assert data["result"]["file_name"] == "test_file.txt"
        assert "scan_id" in data["result"]
        
        # Check if the rule matched
        assert len(data["result"]["matches"]) == 1
        assert data["result"]["matches"][0]["rule"] == "TestRule"
    finally:
        # Clean up
        os.unlink(temp_file_path)


def test_get_scan_result(test_client: TestClient, auth_headers, monkeypatch):
    """Test getting a scan result by ID."""
    # Mock the get_result method in storage to return a test result
    from yaraflux_mcp_server.models import YaraScanResult
    from yaraflux_mcp_server.storage import get_storage_client, StorageClient
    
    # Create a test scan result
    test_result = YaraScanResult(
        file_name="result_test_file.txt",
        file_size=100,
        file_hash="result_test_hash",
        scan_time=0.1,
        matches=[]
    )
    test_id = test_result.scan_id
    
    # Mock the storage client's get_result method
    class MockStorageClient(StorageClient):
        def save_rule(self, *args, **kwargs): pass
        def get_rule(self, *args, **kwargs): pass
        def delete_rule(self, *args, **kwargs): pass
        def list_rules(self, *args, **kwargs): return []
        def save_sample(self, *args, **kwargs): return "", ""
        def get_sample(self, *args, **kwargs): return b""
        def save_result(self, *args, **kwargs): return ""
        
        def get_result(self, result_id):
            if result_id == str(test_id):
                return test_result.dict()
            raise Exception("Result not found")
    
    # Apply the monkeypatch
    monkeypatch.setattr("yaraflux_mcp_server.storage.get_storage_client", lambda: MockStorageClient())
    
    # Test the get result endpoint
    response = test_client.get(f"/api/v1/scan/result/{test_id}", headers=auth_headers)
    
    assert response.status_code == 200
    data = response.json()
    assert "result" in data
    assert data["result"]["file_name"] == "result_test_file.txt"
    assert data["result"]["scan_id"] == str(test_id)


def test_get_nonexistent_scan_result(test_client: TestClient, auth_headers):
    """Test getting a scan result that doesn't exist."""
    response = test_client.get(
        "/api/v1/scan/result/00000000-0000-0000-0000-000000000000",
        headers=auth_headers
    )
    
    assert response.status_code == 404
    data = response.json()
    assert "detail" in data
