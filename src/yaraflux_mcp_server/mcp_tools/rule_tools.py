"""YARA rule management tools for Claude MCP integration.

This module provides tools for managing YARA rules, including listing,
adding, updating, validating, and deleting rules.
"""

import logging
import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

from ..yara_service import YaraError, yara_service
from .base import register_tool

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
    try:
        # Get rules from the YARA service
        rules = yara_service.list_rules(source)

        # Convert to dict for serialization
        return [rule.dict() for rule in rules]
    except YaraError as e:
        logger.error(f"Error listing YARA rules: {str(e)}")
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
    try:
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
    except YaraError as e:
        logger.error(f"Error getting YARA rule {rule_name}: {str(e)}")
        return {"name": rule_name, "source": source, "error": str(e)}


@register_tool()
def validate_yara_rule(content: str) -> Dict[str, Any]:
    """Validate a YARA rule.

    Args:
        content: YARA rule content to validate

    Returns:
        Validation result
    """
    try:
        # Create a temporary rule name for validation
        temp_rule_name = f"validate_{int(datetime.utcnow().timestamp())}.yar"

        # Attempt to add the rule (this will validate it)
        yara_service.add_rule(temp_rule_name, content)

        # Rule is valid, delete it
        yara_service.delete_rule(temp_rule_name)

        return {"valid": True, "message": "Rule is valid"}
    except YaraError as e:
        logger.error(f"YARA rule validation error: {str(e)}")
        return {"valid": False, "message": str(e)}


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
    try:
        # Add the rule
        metadata = yara_service.add_rule(name, content, source)

        return {"success": True, "message": f"Rule {name} added successfully", "metadata": metadata.dict()}
    except YaraError as e:
        logger.error(f"Error adding YARA rule {name}: {str(e)}")
        return {"success": False, "message": str(e)}


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
    try:
        # Update the rule
        metadata = yara_service.update_rule(name, content, source)

        return {"success": True, "message": f"Rule {name} updated successfully", "metadata": metadata.dict()}
    except YaraError as e:
        logger.error(f"Error updating YARA rule {name}: {str(e)}")
        return {"success": False, "message": str(e)}


@register_tool()
def delete_yara_rule(name: str, source: str = "custom") -> Dict[str, Any]:
    """Delete a YARA rule.

    Args:
        name: Name of the rule
        source: Source of the rule ("custom" or "community")

    Returns:
        Result of the operation
    """
    try:
        # Delete the rule
        result = yara_service.delete_rule(name, source)

        if result:
            return {"success": True, "message": f"Rule {name} deleted successfully"}
        else:
            return {"success": False, "message": f"Rule {name} not found"}
    except YaraError as e:
        logger.error(f"Error deleting YARA rule {name}: {str(e)}")
        return {"success": False, "message": str(e)}


@register_tool()
def import_threatflux_rules(url: Optional[str] = None, branch: str = "master") -> Dict[str, Any]:
    """Import ThreatFlux YARA rules from GitHub.

    Args:
        url: URL to the GitHub repository (if None, use default ThreatFlux repository)
        branch: Branch name to import from

    Returns:
        Import result
    """
    if url is None:
        url = "https://github.com/ThreatFlux/YARA-Rules"

    try:
        import_count = 0
        error_count = 0

        # Create a temporary directory for downloading the repo
        with tempfile.TemporaryDirectory() as temp_dir:
            # Set up paths
            temp_path = Path(temp_dir)

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
                        dir_url = f"{import_path}/{directory}"

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
    except Exception as e:
        logger.error(f"Error importing rules from {url}: {str(e)}")
        return {"success": False, "message": str(e)}
