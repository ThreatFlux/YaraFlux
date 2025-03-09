"""YARA rule management tools for Claude MCP integration.

This module provides tools for managing YARA rules, including listing,
adding, updating, validating, and deleting rules. It uses standardized
error handling and parameter validation.
"""

import logging
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

from yaraflux_mcp_server.mcp_tools.base import register_tool
from yaraflux_mcp_server.utils.error_handling import safe_execute
from yaraflux_mcp_server.yara_service import YaraError, yara_service

# Configure logging
logger = logging.getLogger(__name__)


@register_tool()
def list_yara_rules(source: Optional[str] = None) -> List[Dict[str, Any]]:
    """List available YARA rules.

    Args:
        source: Optional source filter ("custom" or "community")

    Returns:
        List of YARA rule metadata objects
    """

    def _list_yara_rules(source: Optional[str] = None) -> List[Dict[str, Any]]:
        """Implementation function for list_yara_rules."""
        # Validate source if provided
        if source and source not in ["custom", "community", "all"]:
            raise ValueError(f"Invalid source: {source}. Must be 'custom', 'community', or 'all'")

        # Get rules from the YARA service
        rules = yara_service.list_rules(None if source == "all" else source)

        # Convert to dict for serialization
        return [rule.dict() for rule in rules]

    # Execute with standardized error handling
    result = safe_execute("list_yara_rules", _list_yara_rules, source=source)

    # Extract result value or return empty list on error
    if result.get("success", False):
        return result.get("result", [])
    return []


@register_tool()
def get_yara_rule(rule_name: str, source: str = "custom") -> Dict[str, Any]:
    """Get a YARA rule's content.

    Args:
        rule_name: Name of the rule to get
        source: Source of the rule ("custom" or "community")

    Returns:
        Rule content and metadata
    """

    def _get_yara_rule(rule_name: str, source: str) -> Dict[str, Any]:
        """Implementation function for get_yara_rule."""
        # Validate source
        if source not in ["custom", "community"]:
            raise ValueError(f"Invalid source: {source}. Must be 'custom' or 'community'")

        # Get rule content
        content = yara_service.get_rule(rule_name, source)

        # Get rule metadata
        rules = yara_service.list_rules(source)
        metadata = None
        for rule in rules:
            if rule.name == rule_name:
                metadata = rule
                break

        # Return content and metadata
        return {
            "name": rule_name,
            "source": source,
            "content": content,
            "metadata": metadata.dict() if metadata else {},
        }

    # Execute with standardized error handling
    return safe_execute(
        "get_yara_rule",
        _get_yara_rule,
        rule_name=rule_name,
        source=source,
        error_handlers={YaraError: lambda e: {"name": rule_name, "source": source, "error": str(e)}},
    )


@register_tool()
def validate_yara_rule(content: str) -> Dict[str, Any]:
    """Validate a YARA rule.

    Args:
        content: YARA rule content to validate

    Returns:
        Validation result with detailed error information if invalid
    """

    def _validate_yara_rule(content: str) -> Dict[str, Any]:
        """Implementation function for validate_yara_rule."""
        if not content.strip():
            raise ValueError("Rule content cannot be empty")

        try:
            # Try to directly validate using YARA
            import yara # noqa: F401

            # This will compile the rule but not save it
            compiled_rule = yara.compile(source=content)

            # If we reach here, the rule is valid
            return {"valid": True, "message": "Rule is valid"}

        except Exception as e:
            # Capture the original compilation error
            error_message = str(e)
            logger.debug(f"YARA compilation error: {error_message}")
            raise YaraError(f"Rule validation failed: {error_message}")

    # Execute with standardized error handling
    result = safe_execute(
        "validate_yara_rule",
        _validate_yara_rule,
        content=content,
        error_handlers={
            YaraError: lambda e: {"valid": False, "message": str(e), "error_type": "YaraError"},
            ValueError: lambda e: {"valid": False, "message": str(e), "error_type": "ValueError"},
            Exception: lambda e: {
                "valid": False,
                "message": f"Unexpected error: {str(e)}",
                "error_type": e.__class__.__name__,
            },
        },
    )

    # Result will already have the right structure from error_handlers
    return result


@register_tool()
def add_yara_rule(name: str, content: str, source: str = "custom") -> Dict[str, Any]:
    """Add a new YARA rule.

    Args:
        name: Name of the rule
        content: YARA rule content
        source: Source of the rule ("custom" or "community")

    Returns:
        Result of the operation
    """

    def _add_yara_rule(name: str, content: str, source: str) -> Dict[str, Any]:
        """Implementation function for add_yara_rule."""
        # Validate source
        if source not in ["custom", "community"]:
            raise ValueError(f"Invalid source: {source}. Must be 'custom' or 'community'")

        # Ensure rule name has .yar extension
        if not name.endswith(".yar"):
            name = f"{name}.yar"

        # Validate content
        if not content.strip():
            raise ValueError("Rule content cannot be empty")

        # Add the rule
        metadata = yara_service.add_rule(name, content, source)

        return {"success": True, "message": f"Rule {name} added successfully", "metadata": metadata.dict()}

    # Execute with standardized error handling
    return safe_execute(
        "add_yara_rule",
        _add_yara_rule,
        name=name,
        content=content,
        source=source,
        error_handlers={
            YaraError: lambda e: {"success": False, "message": str(e)},
            ValueError: lambda e: {"success": False, "message": str(e)},
        },
    )


@register_tool()
def update_yara_rule(name: str, content: str, source: str = "custom") -> Dict[str, Any]:
    """Update an existing YARA rule.

    Args:
        name: Name of the rule
        content: Updated YARA rule content
        source: Source of the rule ("custom" or "community")

    Returns:
        Result of the operation
    """

    def _update_yara_rule(name: str, content: str, source: str) -> Dict[str, Any]:
        """Implementation function for update_yara_rule."""
        # Validate source
        if source not in ["custom", "community"]:
            raise ValueError(f"Invalid source: {source}. Must be 'custom' or 'community'")

        # Ensure rule exists
        yara_service.get_rule(name, source)  # Will raise YaraError if not found

        # Validate content
        if not content.strip():
            raise ValueError("Rule content cannot be empty")

        # Update the rule
        metadata = yara_service.update_rule(name, content, source)

        return {"success": True, "message": f"Rule {name} updated successfully", "metadata": metadata.dict()}

    # Execute with standardized error handling
    return safe_execute(
        "update_yara_rule",
        _update_yara_rule,
        name=name,
        content=content,
        source=source,
        error_handlers={
            YaraError: lambda e: {"success": False, "message": str(e)},
            ValueError: lambda e: {"success": False, "message": str(e)},
        },
    )


@register_tool()
def delete_yara_rule(name: str, source: str = "custom") -> Dict[str, Any]:
    """Delete a YARA rule.

    Args:
        name: Name of the rule
        source: Source of the rule ("custom" or "community")

    Returns:
        Result of the operation
    """

    def _delete_yara_rule(name: str, source: str) -> Dict[str, Any]:
        """Implementation function for delete_yara_rule."""
        # Validate source
        if source not in ["custom", "community"]:
            raise ValueError(f"Invalid source: {source}. Must be 'custom' or 'community'")

        # Delete the rule
        result = yara_service.delete_rule(name, source)

        if result:
            return {"success": True, "message": f"Rule {name} deleted successfully"}
        else:
            return {"success": False, "message": f"Rule {name} not found"}

    # Execute with standardized error handling
    return safe_execute(
        "delete_yara_rule",
        _delete_yara_rule,
        name=name,
        source=source,
        error_handlers={
            YaraError: lambda e: {"success": False, "message": str(e)},
            ValueError: lambda e: {"success": False, "message": str(e)},
        },
    )


@register_tool()
def import_threatflux_rules(url: Optional[str] = None, branch: str = "master") -> Dict[str, Any]:
    """Import ThreatFlux YARA rules from GitHub.

    Args:
        url: URL to the GitHub repository (if None, use default ThreatFlux repository)
        branch: Branch name to import from

    Returns:
        Import result
    """

    def _import_threatflux_rules(url: Optional[str], branch: str) -> Dict[str, Any]:
        """Implementation function for import_threatflux_rules."""
        # Set default URL if not provided
        if url is None:
            url = "https://github.com/ThreatFlux/YARA-Rules"

        # Validate branch
        if not branch:
            branch = "master"

        import_count = 0
        error_count = 0

        # Create a temporary directory for downloading the repo
        with tempfile.TemporaryDirectory() as temp_dir:
            # Set up paths
            temp_path = Path(temp_dir)
            if not temp_path.exists():
                temp_path.mkdir(parents=True)

            # Clone or download the repository
            if "github.com" in url:
                # Format for raw content
                raw_url = url.replace("github.com", "raw.githubusercontent.com")
                if raw_url.endswith("/"):
                    raw_url = raw_url[:-1]

                # Get the repository contents
                import_path = f"{raw_url}/{branch}"

                # Download and process index.json if available
                try:
                    index_url = f"{import_path}/index.json"
                    response = httpx.get(index_url, follow_redirects=True)
                    if response.status_code == 200:
                        # Parse index
                        index = response.json()
                        rule_files = index.get("rules", [])

                        # Download each rule file
                        for rule_file in rule_files:
                            rule_url = f"{import_path}/{rule_file}"
                            try:
                                rule_response = httpx.get(rule_url, follow_redirects=True)
                                if rule_response.status_code == 200:
                                    rule_content = rule_response.text
                                    rule_name = os.path.basename(rule_file)

                                    # Add the rule
                                    yara_service.add_rule(rule_name, rule_content, "community")
                                    import_count += 1
                                else:
                                    logger.warning(
                                        f"Failed to download rule {rule_file}: HTTP {rule_response.status_code}"
                                    )
                                    error_count += 1
                            except Exception as e:
                                logger.error(f"Error downloading rule {rule_file}: {str(e)}")
                                error_count += 1
                    else:
                        # No index.json, try a different approach
                        raise Exception("No index.json found")
                except Exception:
                    # Try fetching individual .yar files from specific directories
                    directories = ["malware", "general", "packer", "persistence"]

                    for directory in directories:
                        try:
                            # This is a simple approach, in a real implementation, you'd need to
                            # get the directory listing from the GitHub API or parse HTML
                            common_rule_files = [
                                f"{directory}/apt.yar",
                                f"{directory}/generic.yar",
                                f"{directory}/capabilities.yar",
                                f"{directory}/indicators.yar",
                            ]

                            for rule_file in common_rule_files:
                                rule_url = f"{import_path}/{rule_file}"
                                try:
                                    rule_response = httpx.get(rule_url, follow_redirects=True)
                                    if rule_response.status_code == 200:
                                        rule_content = rule_response.text
                                        rule_name = os.path.basename(rule_file)

                                        # Add the rule
                                        yara_service.add_rule(rule_name, rule_content, "community")
                                        import_count += 1
                                except Exception:
                                    # Rule file not found, skip
                                    continue
                        except Exception as e:
                            logger.warning(f"Error processing directory {directory}: {str(e)}")
            else:
                # Local path
                import_path = Path(url)
                if not import_path.exists():
                    raise YaraError(f"Local path not found: {url}")

                # Process .yar files
                for rule_file in import_path.glob("**/*.yar"):
                    try:
                        with open(rule_file, "r", encoding="utf-8") as f:
                            rule_content = f.read()

                        rule_name = rule_file.name
                        yara_service.add_rule(rule_name, rule_content, "community")
                        import_count += 1
                    except Exception as e:
                        logger.error(f"Error importing rule {rule_file}: {str(e)}")
                        error_count += 1

        # Reload rules
        yara_service.load_rules()

        return {
            "success": True,
            "message": f"Imported {import_count} rules from {url} ({error_count} errors)",
            "import_count": import_count,
            "error_count": error_count,
        }

    # Execute with standardized error handling
    return safe_execute(
        "import_threatflux_rules",
        _import_threatflux_rules,
        url=url,
        branch=branch,
        error_handlers={
            YaraError: lambda e: {"success": False, "message": str(e)},
            Exception: lambda e: {"success": False, "message": f"Error importing rules: {str(e)}"},
        },
    )
