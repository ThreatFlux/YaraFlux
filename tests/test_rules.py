"""Tests for YARA rule functionality."""

import pytest
from fastapi.testclient import TestClient


def test_list_rules_empty(test_client: TestClient, auth_headers):
    """Test listing rules when none exist."""
    response = test_client.get("/api/v1/rules/", headers=auth_headers)
    
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 0


def test_create_rule(test_client: TestClient, auth_headers, sample_yara_rule):
    """Test creating a new YARA rule."""
    response = test_client.post(
        "/api/v1/rules/",
        json={
            "name": "test_rule",
            "content": sample_yara_rule
        },
        headers=auth_headers
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "test_rule.yar"
    assert data["source"] == "custom"
    
    # Check that rule was created
    response = test_client.get("/api/v1/rules/", headers=auth_headers)
    data = response.json()
    assert len(data) == 1
    assert data[0]["name"] == "test_rule.yar"


def test_get_rule(test_client: TestClient, auth_headers, sample_yara_rule):
    """Test getting a YARA rule."""
    # First create a rule
    test_client.post(
        "/api/v1/rules/",
        json={
            "name": "get_test_rule",
            "content": sample_yara_rule
        },
        headers=auth_headers
    )
    
    # Get the rule
    response = test_client.get("/api/v1/rules/get_test_rule", headers=auth_headers)
    
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "get_test_rule"
    assert data["source"] == "custom"
    assert "content" in data
    assert sample_yara_rule.strip() in data["content"]


def test_get_nonexistent_rule(test_client: TestClient, auth_headers):
    """Test getting a rule that doesn't exist."""
    response = test_client.get("/api/v1/rules/nonexistent_rule", headers=auth_headers)
    
    assert response.status_code == 404
    data = response.json()
    assert "detail" in data


def test_update_rule(test_client: TestClient, auth_headers, sample_yara_rule):
    """Test updating a YARA rule."""
    # First create a rule
    test_client.post(
        "/api/v1/rules/",
        json={
            "name": "update_test_rule",
            "content": sample_yara_rule
        },
        headers=auth_headers
    )
    
    # Update the rule
    updated_content = sample_yara_rule.replace("test string", "updated test string")
    response = test_client.put(
        "/api/v1/rules/update_test_rule",
        json=updated_content,
        headers=auth_headers
    )
    
    assert response.status_code == 200
    
    # Get the rule to check the update
    response = test_client.get("/api/v1/rules/update_test_rule", headers=auth_headers)
    data = response.json()
    assert "updated test string" in data["content"]


def test_delete_rule(test_client: TestClient, auth_headers, sample_yara_rule):
    """Test deleting a YARA rule."""
    # First create a rule
    test_client.post(
        "/api/v1/rules/",
        json={
            "name": "delete_test_rule",
            "content": sample_yara_rule
        },
        headers=auth_headers
    )
    
    # Delete the rule
    response = test_client.delete("/api/v1/rules/delete_test_rule", headers=auth_headers)
    
    assert response.status_code == 200
    data = response.json()
    assert "message" in data
    
    # Check that rule is gone
    response = test_client.get("/api/v1/rules/delete_test_rule", headers=auth_headers)
    assert response.status_code == 404


def test_validate_rule(test_client: TestClient, auth_headers, sample_yara_rule):
    """Test validating a YARA rule."""
    response = test_client.post(
        "/api/v1/rules/validate",
        json=sample_yara_rule,
        headers=auth_headers
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["valid"] is True


def test_validate_invalid_rule(test_client: TestClient, auth_headers):
    """Test validating an invalid YARA rule."""
    invalid_rule = """
    rule InvalidRule {
        strings:
            $test_string = "test string"
        condition:
            invalid_syntax
    }
    """
    
    response = test_client.post(
        "/api/v1/rules/validate",
        json=invalid_rule,
        headers=auth_headers
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["valid"] is False
    assert "message" in data
