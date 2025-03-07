"""YARA scanning service."""

import hashlib
import os
import uuid
from datetime import datetime, UTC
from io import BytesIO
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

import yara
from fastapi import UploadFile
import httpx

from .config import settings
from .models import YaraMatch, YaraRuleMetadata, YaraScanResult
from .storage import StorageClient, StorageError, get_storage_client

class YaraError(Exception):
    """Custom exception for YARA-related errors."""

class YaraService:
    """Service for managing and using YARA rules."""

    def __init__(self, storage_client: Optional[StorageClient] = None):
        """Initialize the service.

        Args:
            storage_client: Optional storage client instance
        """
        self.storage = storage_client or get_storage_client()
        self._rules_cache: Dict[str, yara.Rules] = {}
        self._include_callbacks: Dict[str, Dict[str, Callable]] = {}
        self.settings = settings

    def add_rule(self, rule_name: str, content: str, source: str = "custom") -> YaraRuleMetadata:
        """Add a new YARA rule.

        Args:
            rule_name: Name of the rule file
            content: Rule content
            source: Source of the rule (default: custom)

        Returns:
            Rule metadata

        Raises:
            YaraError: If rule compilation fails or storage fails
        """
        try:
            # Test compilation first
            yara.compile(source=content, error_on_warning=True)

            # Save the rule
            self.storage.save_rule(rule_name, content, source)

            # Create and return metadata
            return YaraRuleMetadata(
                name=rule_name,
                source=source,
                created=datetime.now(UTC),
                is_compiled=True,
            )
        except yara.Error as e:
            raise YaraError(f"Failed to compile rule: {str(e)}")
        except StorageError as e:
            raise YaraError(f"Failed to save rule: {str(e)}")

    def update_rule(self, rule_name: str, content: str, source: str = "custom") -> YaraRuleMetadata:
        """Update an existing YARA rule.

        Args:
            rule_name: Name of the rule
            content: New rule content
            source: Source of the rule

        Returns:
            Updated rule metadata

        Raises:
            YaraError: If rule not found or compilation fails
        """
        try:
            # Verify rule exists
            self.storage.get_rule(rule_name, source)

            # Test compilation
            yara.compile(source=content, error_on_warning=True)

            # Save updated rule
            self.storage.save_rule(rule_name, content, source)

            # Update metadata
            metadata = YaraRuleMetadata(
                name=rule_name,
                source=source,
                created=datetime.now(UTC),
                modified=datetime.now(UTC),
                is_compiled=True,
            )

            # Clear any cached compilation
            cache_key = f"{source}:{rule_name}"
            self._rules_cache.pop(cache_key, None)

            return metadata

        except (yara.Error, StorageError) as e:
            raise YaraError(f"Failed to update rule: {str(e)}")

    def delete_rule(self, rule_name: str, source: str = "custom") -> bool:
        """Delete a YARA rule.

        Args:
            rule_name: Name of the rule
            source: Source of the rule

        Returns:
            True if deletion was successful
        """
        # Clear any cached compilation
        cache_key = f"{source}:{rule_name}"
        self._rules_cache.pop(cache_key, None)

        return self.storage.delete_rule(rule_name, source)

    def get_rule(self, rule_name: str, source: str = "custom") -> str:
        """Get a YARA rule's content.

        Args:
            rule_name: Name of the rule
            source: Source of the rule

        Returns:
            Rule content

        Raises:
            YaraError: If rule not found
        """
        try:
            return self.storage.get_rule(rule_name, source)
        except StorageError as e:
            raise YaraError(f"Failed to get rule: {str(e)}")

    def list_rules(self, source: Optional[str] = None) -> List[YaraRuleMetadata]:
        """List available YARA rules.

        Args:
            source: Optional source to filter by

        Returns:
            List of rule metadata
        """
        rules = self.storage.list_rules(source)
        return [
            YaraRuleMetadata(
                name=rule["name"],
                source=rule["source"],
                created=rule["created"],
                modified=rule.get("modified"),
                is_compiled=True
            )
            for rule in rules
        ]

    def load_rules(self, include_default_rules: bool = True) -> None:
        """Load and compile all rules.

        Args:
            include_default_rules: Whether to include default rules
        """
        self._rules_cache.clear()
        for rule in self.list_rules():
            try:
                self._compile_rule(rule.name, rule.source)
            except YaraError:
                continue

    def match_file(self, file_path: Union[str, Path]) -> YaraScanResult:
        """Match YARA rules against a file.

        Args:
            file_path: Path to the file to scan

        Returns:
            Scan result

        Raises:
            YaraError: If scanning fails
        """
        try:
            file_path = Path(file_path)
            file_size = file_path.stat().st_size

            if file_size > self.settings.YARA_MAX_FILE_SIZE:
                raise YaraError(f"File too large: {file_size} bytes")

            with open(file_path, "rb") as f:
                file_content = f.read()
                file_hash = hashlib.sha256(file_content).hexdigest()

            matches = []
            for rule_cache_key, compiled_rule in self._rules_cache.items():
                source = rule_cache_key.split(":")[0]
                try:
                    rule_matches = compiled_rule.match(data=file_content)
                    for match in rule_matches:
                        matches.append(self._process_match(match, source))
                except yara.Error:
                    continue

            result = YaraScanResult(
                scan_id=uuid.uuid4(),
                file_name=file_path.name,
                file_size=file_size,
                file_hash=file_hash,
                matches=matches,
            )

            # Save result
            self.storage.save_result(str(result.scan_id), result.model_dump())

            return result

        except (OSError, yara.Error) as e:
            raise YaraError(f"Error scanning file: {str(e)}")

    def match_data(self, data: Union[bytes, BytesIO], filename: str) -> YaraScanResult:
        """Match YARA rules against binary data.

        Args:
            data: Data to scan
            filename: Name for the scanned data

        Returns:
            Scan result

        Raises:
            YaraError: If scanning fails
        """
        try:
            if isinstance(data, BytesIO):
                content = data.getvalue()
            else:
                content = data

            if len(content) > self.settings.YARA_MAX_FILE_SIZE:
                raise YaraError(f"Data too large: {len(content)} bytes")

            file_hash = hashlib.sha256(content).hexdigest()
            matches = []

            for rule_cache_key, compiled_rule in self._rules_cache.items():
                source = rule_cache_key.split(":")[0]
                try:
                    rule_matches = compiled_rule.match(data=content)
                    for match in rule_matches:
                        matches.append(self._process_match(match, source))
                except yara.Error:
                    continue

            result = YaraScanResult(
                scan_id=uuid.uuid4(),
                file_name=filename,
                file_size=len(content),
                file_hash=file_hash,
                matches=matches,
            )

            # Save result
            self.storage.save_result(str(result.scan_id), result.model_dump())

            return result

        except yara.Error as e:
            raise YaraError(f"Error scanning data: {str(e)}")

    async def fetch_and_scan(self, url: str) -> YaraScanResult:
        """Fetch and scan a URL.

        Args:
            url: URL to fetch and scan

        Returns:
            Scan result

        Raises:
            YaraError: If fetching or scanning fails
        """
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(url)
                response.raise_for_status()

                content = response.content
                filename = url.split("/")[-1] or "downloaded_file"

                return self.match_data(content, filename)

        except httpx.HTTPError as e:
            raise YaraError(f"Failed to fetch URL: {str(e)}")

    def _compile_rule(self, rule_name: str, source: str = "custom") -> yara.Rules:
        """Compile a single YARA rule from storage.

        Args:
            rule_name: Name of the rule
            source: Source of the rule

        Returns:
            Compiled YARA rules object

        Raises:
            YaraError: If rule compilation fails
        """
        # Check for an existing compiled rule
        cache_key = f"{source}:{rule_name}"
        if cache_key in self._rules_cache:
            return self._rules_cache[cache_key]

        try:
            # Get the rule content from storage
            rule_content = self.storage.get_rule(rule_name, source)

            # Register an include callback for this rule
            self._register_include_callback(source, rule_name)

            # Compile the rule
            compiled_rule = yara.compile(
                source=rule_content,
                includes=True,
                include_callback=self._get_include_callback(source),
                error_on_warning=True
            )

            # Cache the compiled rule
            self._rules_cache[cache_key] = compiled_rule

            return compiled_rule
        except yara.Error as e:
            raise YaraError(f"Failed to compile rule {rule_name}: {str(e)}")
        except StorageError as e:
            raise YaraError(f"Failed to load rule {rule_name}: {str(e)}")

    def _register_include_callback(self, source: str, rule_name: str) -> None:
        """Register a callback for handling includes in a rule."""
        if source not in self._include_callbacks:
            self._include_callbacks[source] = {}

        def callback(requested_filename: str, _: Any = None) -> bytes:
            try:
                content = self.storage.get_rule(requested_filename, source)
                return content.encode()
            except StorageError as e:
                raise YaraError(f"Failed to load included rule {requested_filename}: {str(e)}")

        self._include_callbacks[source][rule_name] = callback

    def _get_include_callback(self, source: str) -> Callable:
        """Get the include callback for a source."""
        def callback(requested_filename: str, _: Any = None) -> bytes:
            for rule_callbacks in self._include_callbacks[source].values():
                try:
                    return rule_callbacks(requested_filename)
                except YaraError:
                    continue
            raise YaraError(f"Failed to load included rule {requested_filename}")

        return callback

    def _process_match(self, match: Any, source: str) -> YaraMatch:
        """Process a YARA match result.

        Args:
            match: YARA match object
            source: Rule source

        Returns:
            Processed match result
        """
        try:
            strings = []
            for offset, identifier, data in match.strings:
                strings.append({
                    "offset": offset,
                    "name": identifier,
                    "data": data
                })

            return YaraMatch(
                rule=match.rule,
                namespace=match.namespace,
                meta=match.meta or {},
                strings=strings
            )
        except Exception as e:
            raise YaraError(f"Error processing YARA match: {str(e)}")

# Global instance
yara_service = YaraService()
