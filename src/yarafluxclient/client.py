"""YaraFlux MCP Client.

This module provides a client for interacting with the YaraFlux MCP Server.
"""

import json
import logging
import os
from typing import Any, Dict, List, Optional, Union
import urllib.parse

import httpx

from yarafluxclient.exceptions import (
    AuthenticationError,
    ConnectionError,
    ResourceNotFoundError,
    ServerError,
    ValidationError,
    YaraFluxClientError,
)

# Configure logging
logger = logging.getLogger(__name__)


class YaraFluxClient:
    """Client for interacting with YaraFlux MCP Server."""

    def __init__(
        self,
        base_url: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        token: Optional[str] = None,
        timeout: int = 30,
    ):
        """Initialize the client.

        Args:
            base_url: Base URL of the YaraFlux MCP Server
            username: Username for authentication
            password: Password for authentication
            token: JWT token for authentication (alternative to username/password)
            timeout: Request timeout in seconds
        """
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._token = token
        self._username = username
        self._password = password
        self._client = httpx.Client(timeout=timeout)

        # Authenticate if credentials are provided
        if token is None and username is not None and password is not None:
            self.authenticate(username, password)

    def authenticate(self, username: str, password: str) -> str:
        """Authenticate with the server and get a JWT token.

        Args:
            username: Username
            password: Password

        Returns:
            JWT token

        Raises:
            AuthenticationError: If authentication fails
        """
        try:
            response = self._client.post(
                f"{self.base_url}/api/v1/auth/token",
                data={"username": username, "password": password},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            response.raise_for_status()
            token_data = response.json()
            self._token = token_data["access_token"]
            logger.info(f"Authenticated as {username}")
            return self._token
        except httpx.HTTPStatusError as e:
            logger.error(f"Authentication failed: {e}")
            raise AuthenticationError(f"Authentication failed: {e}")
        except httpx.RequestError as e:
            logger.error(f"Connection error during authentication: {e}")
            raise ConnectionError(f"Connection error: {e}")

    @property
    def auth_headers(self) -> Dict[str, str]:
        """Get authentication headers.

        Returns:
            Authentication headers

        Raises:
            AuthenticationError: If not authenticated
        """
        if self._token is None:
            raise AuthenticationError("Not authenticated. Call authenticate() first.")
        return {"Authorization": f"Bearer {self._token}"}

    def _handle_response(self, response: httpx.Response) -> Any:
        """Handle the API response.

        Args:
            response: HTTP response

        Returns:
            Response data

        Raises:
            AuthenticationError: If authentication fails
            ValidationError: If validation fails
            ResourceNotFoundError: If resource not found
            ServerError: If server error occurs
        """
        try:
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            status_code = e.response.status_code
            try:
                error_data = e.response.json()
                error_detail = error_data.get("detail", str(e))
            except Exception:
                error_detail = str(e)

            if status_code == 401:
                logger.error(f"Authentication error: {error_detail}")
                raise AuthenticationError(f"Authentication error: {error_detail}")
            elif status_code == 400:
                logger.error(f"Validation error: {error_detail}")
                raise ValidationError(f"Validation error: {error_detail}")
            elif status_code == 404:
                logger.error(f"Resource not found: {error_detail}")
                raise ResourceNotFoundError(f"Resource not found: {error_detail}")
            elif status_code >= 500:
                logger.error(f"Server error: {error_detail}")
                raise ServerError(f"Server error: {error_detail}")
            else:
                logger.error(f"YaraFlux client error: {error_detail}")
                raise YaraFluxClientError(f"YaraFlux client error: {error_detail}")
        except httpx.RequestError as e:
            logger.error(f"Connection error: {e}")
            raise ConnectionError(f"Connection error: {e}")
        except json.JSONDecodeError as e:
            if response.status_code == 200 and not response.content:
                return {}
            logger.error(f"Invalid JSON response: {e}")
            raise YaraFluxClientError(f"Invalid JSON response: {e}")

    # YARA Rule Management

    def list_rules(self, source: Optional[str] = None) -> List[Dict[str, Any]]:
        """List YARA rules.

        Args:
            source: Optional source filter ("custom" or "community")

        Returns:
            List of rule metadata
        """
        url = f"{self.base_url}/api/v1/rules/"
        if source:
            url += f"?source={source}"

        response = self._client.get(url, headers=self.auth_headers)
        return self._handle_response(response)

    def get_rule(self, rule_name: str, source: str = "custom") -> Dict[str, Any]:
        """Get a YARA rule.

        Args:
            rule_name: Name of the rule
            source: Source of the rule ("custom" or "community")

        Returns:
            Rule data including content and metadata
        """
        url = f"{self.base_url}/api/v1/rules/{rule_name}"
        if source:
            url += f"?source={source}"

        response = self._client.get(url, headers=self.auth_headers)
        return self._handle_response(response)

    def get_rule_content(self, rule_name: str, source: str = "custom") -> str:
        """Get a YARA rule's raw content.

        Args:
            rule_name: Name of the rule
            source: Source of the rule ("custom" or "community")

        Returns:
            Rule content as plain text
        """
        url = f"{self.base_url}/api/v1/rules/{rule_name}/raw"
        if source:
            url += f"?source={source}"

        response = self._client.get(url, headers=self.auth_headers)
        if response.status_code != 200:
            self._handle_response(response)  # Will raise appropriate exception
        return response.text

    def create_rule(
        self,
        name: str,
        content: str,
        source: str = "custom",
        author: Optional[str] = None,
        description: Optional[str] = None,
        reference: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Create a new YARA rule.

        Args:
            name: Name of the rule
            content: YARA rule content
            source: Source of the rule ("custom" or "community")
            author: Optional author name
            description: Optional description
            reference: Optional reference URL
            tags: Optional list of tags

        Returns:
            Created rule metadata
        """
        # Use the plain text endpoint for simplicity
        url = f"{self.base_url}/api/v1/rules/plain"
        params = {"rule_name": name, "source": source}
        
        # Prepare headers
        headers = self.auth_headers.copy()
        headers["Content-Type"] = "text/plain"
        
        response = self._client.post(
            url, 
            params=params, 
            content=content,
            headers=headers
        )
        return self._handle_response(response)

    def update_rule(
        self, rule_name: str, content: str, source: str = "custom"
    ) -> Dict[str, Any]:
        """Update an existing YARA rule.

        Args:
            rule_name: Name of the rule
            content: Updated YARA rule content
            source: Source of the rule ("custom" or "community")

        Returns:
            Updated rule metadata
        """
        # Use the plain text endpoint for simplicity
        url = f"{self.base_url}/api/v1/rules/{rule_name}/plain"
        params = {"source": source}
        
        # Prepare headers
        headers = self.auth_headers.copy()
        headers["Content-Type"] = "text/plain"
        
        response = self._client.put(
            url, 
            params=params, 
            content=content,
            headers=headers
        )
        return self._handle_response(response)

    def delete_rule(self, rule_name: str, source: str = "custom") -> Dict[str, Any]:
        """Delete a YARA rule.

        Args:
            rule_name: Name of the rule
            source: Source of the rule ("custom" or "community")

        Returns:
            Deletion result
        """
        url = f"{self.base_url}/api/v1/rules/{rule_name}"
        if source:
            url += f"?source={source}"

        response = self._client.delete(url, headers=self.auth_headers)
        return self._handle_response(response)

    def validate_rule(self, content: str) -> Dict[str, Any]:
        """Validate a YARA rule.

        Args:
            content: YARA rule content

        Returns:
            Validation result
        """
        url = f"{self.base_url}/api/v1/rules/validate/plain"
        
        # Prepare headers
        headers = self.auth_headers.copy()
        headers["Content-Type"] = "text/plain"
        
        response = self._client.post(url, content=content, headers=headers)
        return self._handle_response(response)

    def import_rules(
        self, url: Optional[str] = None, branch: str = "master"
    ) -> Dict[str, Any]:
        """Import ThreatFlux YARA rules.

        Args:
            url: URL to the GitHub repository (if None, use default ThreatFlux repository)
            branch: Branch name to import from

        Returns:
            Import result
        """
        api_url = f"{self.base_url}/api/v1/rules/import"
        params = {}
        if url:
            params["url"] = url
        if branch:
            params["branch"] = branch

        response = self._client.post(api_url, params=params, headers=self.auth_headers)
        return self._handle_response(response)

    # Scanning

    def scan_url(
        self,
        url: str,
        rule_names: Optional[List[str]] = None,
        timeout: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Scan a file from a URL with YARA rules.

        Args:
            url: URL of the file to scan
            rule_names: Optional list of rule names to match (if None, match all)
            timeout: Optional timeout in seconds (if None, use default)

        Returns:
            Scan result
        """
        api_url = f"{self.base_url}/api/v1/scan/url"
        data = {"url": url}
        if rule_names:
            data["rule_names"] = rule_names
        if timeout:
            data["timeout"] = timeout

        response = self._client.post(
            api_url, json=data, headers=self.auth_headers
        )
        return self._handle_response(response)

    def get_scan_result(self, scan_id: str) -> Dict[str, Any]:
        """Get a scan result by ID.

        Args:
            scan_id: ID of the scan result

        Returns:
            Scan result
        """
        url = f"{self.base_url}/api/v1/scan/result/{scan_id}"
        response = self._client.get(url, headers=self.auth_headers)
        return self._handle_response(response)

    # MCP Integration

    def get_mcp_tools(self) -> List[Dict[str, Any]]:
        """Get available MCP tools.

        Returns:
            List of MCP tools
        """
        url = f"{self.base_url}/mcp/tools"
        response = self._client.get(url, headers=self.auth_headers)
        return self._handle_response(response)

    def invoke_mcp_tool(self, tool_name: str, parameters: Dict[str, Any]) -> Any:
        """Invoke an MCP tool.

        Args:
            tool_name: Name of the tool
            parameters: Tool parameters

        Returns:
            Tool execution result
        """
        url = f"{self.base_url}/mcp/tools/{tool_name}"
        response = self._client.post(
            url, json=parameters, headers=self.auth_headers
        )
        return self._handle_response(response)
