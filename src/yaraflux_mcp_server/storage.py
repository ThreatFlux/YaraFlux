"""Storage abstraction for YaraFlux MCP Server.

This module provides a storage abstraction layer that supports both local filesystem
and MinIO (S3-compatible) storage. It handles storing and retrieving YARA rules,
samples, and scan results.
"""

import hashlib
import io
import json
import logging
import mimetypes
import os
import shutil
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO, Dict, List, Optional, Tuple, Union

# Configure logging
logger = logging.getLogger(__name__)

# Optional MinIO import - only required if MinIO storage is used
try:
    from minio import Minio
    from minio.error import S3Error

    MINIO_AVAILABLE = True
except ImportError:
    MINIO_AVAILABLE = False

# Handle conditional imports to avoid circular references
if TYPE_CHECKING:
    from yaraflux_mcp_server.config import settings
else:
    from yaraflux_mcp_server.config import settings


class StorageError(Exception):
    """Custom exception for storage-related errors."""

    pass


class StorageClient(ABC):
    """Abstract base class for storage clients."""

    @abstractmethod
    def save_rule(self, rule_name: str, content: str, source: str = "custom") -> str:
        """Save a YARA rule to storage.

        Args:
            rule_name: Name of the rule
            content: YARA rule content
            source: Source of the rule (e.g., "custom" or "community")

        Returns:
            Path or key where the rule was saved
        """
        pass

    @abstractmethod
    def get_rule(self, rule_name: str, source: str = "custom") -> str:
        """Get a YARA rule from storage.

        Args:
            rule_name: Name of the rule
            source: Source of the rule

        Returns:
            Content of the rule

        Raises:
            StorageError: If rule not found
        """
        pass

    @abstractmethod
    def delete_rule(self, rule_name: str, source: str = "custom") -> bool:
        """Delete a YARA rule from storage.

        Args:
            rule_name: Name of the rule
            source: Source of the rule

        Returns:
            True if successful, False otherwise
        """
        pass

    @abstractmethod
    def list_rules(self, source: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all YARA rules in storage.

        Args:
            source: Optional filter by source

        Returns:
            List of rule metadata
        """
        pass

    @abstractmethod
    def save_sample(self, filename: str, content: Union[bytes, BinaryIO]) -> Tuple[str, str]:
        """Save a sample file to storage.

        Args:
            filename: Name of the file
            content: File content as bytes or file-like object

        Returns:
            Tuple of (path/key where sample was saved, sha256 hash)
        """
        pass

    @abstractmethod
    def get_sample(self, sample_id: str) -> bytes:
        """Get a sample from storage.

        Args:
            sample_id: ID of the sample (hash or filename)

        Returns:
            Sample content

        Raises:
            StorageError: If sample not found
        """
        pass

    @abstractmethod
    def save_result(self, result_id: str, content: Dict[str, Any]) -> str:
        """Save a scan result to storage.

        Args:
            result_id: ID for the result
            content: Result data

        Returns:
            Path or key where the result was saved
        """
        pass

    @abstractmethod
    def get_result(self, result_id: str) -> Dict[str, Any]:
        """Get a scan result from storage.

        Args:
            result_id: ID of the result

        Returns:
            Result data

        Raises:
            StorageError: If result not found
        """
        pass


class LocalStorageClient(StorageClient):
    """Storage client that uses local filesystem."""

    def __init__(self):
        """Initialize local storage client."""
        self.rules_dir = settings.YARA_RULES_DIR
        self.samples_dir = settings.YARA_SAMPLES_DIR
        self.results_dir = settings.YARA_RESULTS_DIR

        # Ensure directories exist
        os.makedirs(self.rules_dir, exist_ok=True)
        os.makedirs(self.samples_dir, exist_ok=True)
        os.makedirs(self.results_dir, exist_ok=True)

        # Create source subdirectories for rules
        os.makedirs(self.rules_dir / "community", exist_ok=True)
        os.makedirs(self.rules_dir / "custom", exist_ok=True)

        logger.info(
            f"Initialized local storage: rules={self.rules_dir}, "
            f"samples={self.samples_dir}, results={self.results_dir}"
        )

    def save_rule(self, rule_name: str, content: str, source: str = "custom") -> str:
        """Save a YARA rule to the local filesystem."""
        if not rule_name.endswith(".yar"):
            rule_name = f"{rule_name}.yar"

        source_dir = self.rules_dir / source
        os.makedirs(source_dir, exist_ok=True)

        rule_path = source_dir / rule_name
        try:
            with open(rule_path, "w", encoding="utf-8") as f:
                f.write(content)
            logger.debug(f"Saved rule {rule_name} to {rule_path}")
            return str(rule_path)
        except (IOError, OSError) as e:
            logger.error(f"Failed to save rule {rule_name}: {str(e)}")
            raise StorageError(f"Failed to save rule: {str(e)}")

    def get_rule(self, rule_name: str, source: str = "custom") -> str:
        """Get a YARA rule from the local filesystem."""
        if not rule_name.endswith(".yar"):
            rule_name = f"{rule_name}.yar"

        rule_path = self.rules_dir / source / rule_name
        try:
            with open(rule_path, "r", encoding="utf-8") as f:
                content = f.read()
            return content
        except FileNotFoundError:
            logger.error(f"Rule not found: {rule_name} in {source}")
            raise StorageError(f"Rule not found: {rule_name}")
        except (IOError, OSError) as e:
            logger.error(f"Failed to read rule {rule_name}: {str(e)}")
            raise StorageError(f"Failed to read rule: {str(e)}")

    def delete_rule(self, rule_name: str, source: str = "custom") -> bool:
        """Delete a YARA rule from the local filesystem."""
        if not rule_name.endswith(".yar"):
            rule_name = f"{rule_name}.yar"

        rule_path = self.rules_dir / source / rule_name
        try:
            os.remove(rule_path)
            logger.debug(f"Deleted rule {rule_name} from {source}")
            return True
        except FileNotFoundError:
            logger.warning(f"Rule not found for deletion: {rule_name} in {source}")
            return False
        except (IOError, OSError) as e:
            logger.error(f"Failed to delete rule {rule_name}: {str(e)}")
            raise StorageError(f"Failed to delete rule: {str(e)}")

    def list_rules(self, source: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all YARA rules in the local filesystem."""
        rules = []

        sources = [source] if source else ["custom", "community"]
        for src in sources:
            source_dir = self.rules_dir / src
            if not source_dir.exists():
                continue

            for rule_path in source_dir.glob("*.yar"):
                try:
                    # Get basic file stats
                    stat = rule_path.stat()
                    created = datetime.fromtimestamp(stat.st_ctime)
                    modified = datetime.fromtimestamp(stat.st_mtime)

                    # Extract rule name from path
                    rule_name = rule_path.name

                    rules.append(
                        {
                            "name": rule_name,
                            "source": src,
                            "created": created.isoformat(),
                            "modified": modified.isoformat(),
                            "size": stat.st_size,
                        }
                    )
                except Exception as e:
                    logger.warning(f"Error processing rule {rule_path}: {str(e)}")

        return rules

    def save_sample(self, filename: str, content: Union[bytes, BinaryIO]) -> Tuple[str, str]:
        """Save a sample file to the local filesystem."""
        # Calculate hash for the content
        if hasattr(content, "read"):
            # It's a file-like object, read it first
            content_bytes = content.read()
            if hasattr(content, "seek"):
                content.seek(0)  # Reset position for future reads
        else:
            # It's already bytes
            content_bytes = content

        file_hash = hashlib.sha256(content_bytes).hexdigest()

        # Use hash as directory name for deduplication
        hash_dir = self.samples_dir / file_hash[:2] / file_hash[2:4]
        os.makedirs(hash_dir, exist_ok=True)

        # Save the file with original name inside the hash directory
        file_path = hash_dir / filename
        try:
            with open(file_path, "wb") as f:
                if hasattr(content, "read"):
                    shutil.copyfileobj(content, f)
                else:
                    f.write(content_bytes)

            logger.debug(f"Saved sample {filename} to {file_path} (hash: {file_hash})")
            return str(file_path), file_hash
        except (IOError, OSError) as e:
            logger.error(f"Failed to save sample {filename}: {str(e)}")
            raise StorageError(f"Failed to save sample: {str(e)}")

    def get_sample(self, sample_id: str) -> bytes:
        """Get a sample from the local filesystem."""
        # Check if sample_id is a file path
        if os.path.exists(sample_id):
            try:
                with open(sample_id, "rb") as f:
                    return f.read()
            except (IOError, OSError) as e:
                raise StorageError(f"Failed to read sample: {str(e)}")

        # Check if sample_id is a hash
        if len(sample_id) == 64:  # SHA-256 hash length
            # Try to find the file in the hash directory structure
            hash_dir = self.samples_dir / sample_id[:2] / sample_id[2:4]
            if hash_dir.exists():
                # Look for any file in this directory
                files = list(hash_dir.iterdir())
                if files:
                    try:
                        with open(files[0], "rb") as f:
                            return f.read()
                    except (IOError, OSError) as e:
                        raise StorageError(f"Failed to read sample: {str(e)}")

        raise StorageError(f"Sample not found: {sample_id}")

    def save_result(self, result_id: str, content: Dict[str, Any]) -> str:
        """Save a scan result to the local filesystem."""
        # Ensure the result ID is valid for a filename
        safe_id = result_id.replace("/", "_").replace("\\", "_")

        result_path = self.results_dir / f"{safe_id}.json"
        try:
            with open(result_path, "w", encoding="utf-8") as f:
                json.dump(content, f, indent=2, default=str)

            logger.debug(f"Saved result {result_id} to {result_path}")
            return str(result_path)
        except (IOError, OSError) as e:
            logger.error(f"Failed to save result {result_id}: {str(e)}")
            raise StorageError(f"Failed to save result: {str(e)}")

    def get_result(self, result_id: str) -> Dict[str, Any]:
        """Get a scan result from the local filesystem."""
        # Check if result_id is a file path
        if os.path.exists(result_id) and result_id.endswith(".json"):
            result_path = result_id
        else:
            # Ensure the result ID is valid for a filename
            safe_id = result_id.replace("/", "_").replace("\\", "_")
            result_path = self.results_dir / f"{safe_id}.json"

        try:
            with open(result_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            logger.error(f"Result not found: {result_id}")
            raise StorageError(f"Result not found: {result_id}")
        except (IOError, OSError, json.JSONDecodeError) as e:
            logger.error(f"Failed to read result {result_id}: {str(e)}")
            raise StorageError(f"Failed to read result: {str(e)}")


class MinioStorageClient(StorageClient):
    """Storage client that uses MinIO (S3-compatible storage)."""

    def __init__(self):
        """Initialize MinIO storage client."""
        if not MINIO_AVAILABLE:
            raise ImportError(
                "MinIO support requires the MinIO client library. "
                "Install it with: pip install minio"
            )

        # Validate MinIO settings
        if not all([settings.MINIO_ENDPOINT, settings.MINIO_ACCESS_KEY, settings.MINIO_SECRET_KEY]):
            raise ValueError(
                "MinIO storage requires MINIO_ENDPOINT, MINIO_ACCESS_KEY, "
                "and MINIO_SECRET_KEY settings"
            )

        # Initialize MinIO client
        self.client = Minio(
            endpoint=settings.MINIO_ENDPOINT,
            access_key=settings.MINIO_ACCESS_KEY,
            secret_key=settings.MINIO_SECRET_KEY,
            secure=settings.MINIO_SECURE,
        )

        # Define bucket names
        self.rules_bucket = settings.MINIO_BUCKET_RULES
        self.samples_bucket = settings.MINIO_BUCKET_SAMPLES
        self.results_bucket = settings.MINIO_BUCKET_RESULTS

        # Ensure buckets exist
        self._ensure_bucket_exists(self.rules_bucket)
        self._ensure_bucket_exists(self.samples_bucket)
        self._ensure_bucket_exists(self.results_bucket)

        logger.info(
            f"Initialized MinIO storage: endpoint={settings.MINIO_ENDPOINT}, "
            f"rules={self.rules_bucket}, samples={self.samples_bucket}, "
            f"results={self.results_bucket}"
        )

    def _ensure_bucket_exists(self, bucket_name: str) -> None:
        """Ensure a bucket exists, creating it if necessary."""
        try:
            if not self.client.bucket_exists(bucket_name):
                self.client.make_bucket(bucket_name)
                logger.info(f"Created MinIO bucket: {bucket_name}")
        except S3Error as e:
            logger.error(f"Failed to create MinIO bucket {bucket_name}: {str(e)}")
            raise StorageError(f"Failed to create MinIO bucket: {str(e)}")

    def save_rule(self, rule_name: str, content: str, source: str = "custom") -> str:
        """Save a YARA rule to MinIO storage."""
        if not rule_name.endswith(".yar"):
            rule_name = f"{rule_name}.yar"

        # Define object key
        object_key = f"{source}/{rule_name}"

        # Convert content to bytes
        content_bytes = content.encode("utf-8")
        content_stream = io.BytesIO(content_bytes)

        try:
            # Upload the rule to MinIO
            self.client.put_object(
                bucket_name=self.rules_bucket,
                object_name=object_key,
                data=content_stream,
                length=len(content_bytes),
                content_type="text/plain",
            )
            logger.debug(f"Saved rule {rule_name} to MinIO bucket {self.rules_bucket}/{object_key}")
            return f"{self.rules_bucket}/{object_key}"
        except S3Error as e:
            logger.error(f"Failed to save rule {rule_name} to MinIO: {str(e)}")
            raise StorageError(f"Failed to save rule to MinIO: {str(e)}")

    def get_rule(self, rule_name: str, source: str = "custom") -> str:
        """Get a YARA rule from MinIO storage."""
        if not rule_name.endswith(".yar"):
            rule_name = f"{rule_name}.yar"

        # Define object key
        object_key = f"{source}/{rule_name}"

        try:
            # Get the rule from MinIO
            response = self.client.get_object(bucket_name=self.rules_bucket, object_name=object_key)

            # Read the content and decode
            content = response.read().decode("utf-8")
            response.close()
            response.release_conn()

            return content
        except S3Error as e:
            logger.error(f"Failed to get rule {rule_name} from MinIO: {str(e)}")
            raise StorageError(f"Rule not found or error accessing rule: {str(e)}")

    def delete_rule(self, rule_name: str, source: str = "custom") -> bool:
        """Delete a YARA rule from MinIO storage."""
        if not rule_name.endswith(".yar"):
            rule_name = f"{rule_name}.yar"

        # Define object key
        object_key = f"{source}/{rule_name}"

        try:
            # Check if object exists
            try:
                self.client.stat_object(self.rules_bucket, object_key)
            except S3Error as e:
                if e.code == "NoSuchKey":
                    logger.warning(f"Rule not found for deletion: {rule_name} in {source}")
                    return False
                raise

            # Delete the rule from MinIO
            self.client.remove_object(self.rules_bucket, object_key)
            logger.debug(
                f"Deleted rule {rule_name} from MinIO bucket {self.rules_bucket}/{object_key}"
            )
            return True
        except S3Error as e:
            logger.error(f"Failed to delete rule {rule_name} from MinIO: {str(e)}")
            raise StorageError(f"Failed to delete rule from MinIO: {str(e)}")

    def list_rules(self, source: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all YARA rules in MinIO storage."""
        rules = []

        try:
            # Determine the prefix based on source
            prefix = f"{source}/" if source else None

            # List objects in the bucket with the given prefix
            objects = self.client.list_objects(
                bucket_name=self.rules_bucket, prefix=prefix, recursive=True
            )

            # Process each object
            for obj in objects:
                # Skip if not a YARA rule
                if not obj.object_name.endswith(".yar"):
                    continue

                # Extract source and rule name from object key
                parts = obj.object_name.split("/")
                if len(parts) >= 2:
                    obj_source = parts[0]
                    rule_name = parts[-1]

                    # Skip if source filter is applied and doesn't match
                    if source and obj_source != source:
                        continue

                    rules.append(
                        {
                            "name": rule_name,
                            "source": obj_source,
                            "created": (
                                obj.last_modified.isoformat()
                                if hasattr(obj, "last_modified")
                                else None
                            ),
                            "modified": (
                                obj.last_modified.isoformat()
                                if hasattr(obj, "last_modified")
                                else None
                            ),
                            "size": obj.size,
                        }
                    )

            return rules
        except S3Error as e:
            logger.error(f"Failed to list rules from MinIO: {str(e)}")
            raise StorageError(f"Failed to list rules from MinIO: {str(e)}")

    def save_sample(self, filename: str, content: Union[bytes, BinaryIO]) -> Tuple[str, str]:
        """Save a sample file to MinIO storage."""
        # Calculate hash for the content
        if hasattr(content, "read"):
            # It's a file-like object, read it first
            content_bytes = content.read()
            if hasattr(content, "seek"):
                content.seek(0)  # Reset position for future reads
        else:
            # It's already bytes
            content_bytes = content

        file_hash = hashlib.sha256(content_bytes).hexdigest()

        # Define object key with hash prefix for deduplication
        object_key = f"{file_hash[:2]}/{file_hash[2:4]}/{filename}"

        # Prepare content stream
        if hasattr(content, "read"):
            content_stream = content
            content_length = len(content_bytes)
        else:
            content_stream = io.BytesIO(content_bytes)
            content_length = len(content_bytes)

        # Determine content type
        content_type, _ = mimetypes.guess_type(filename)
        if not content_type:
            content_type = "application/octet-stream"

        try:
            # Upload the sample to MinIO
            self.client.put_object(
                bucket_name=self.samples_bucket,
                object_name=object_key,
                data=content_stream,
                length=content_length,
                content_type=content_type,
            )

            # Add the hash as metadata
            self.client.put_object(
                bucket_name=self.samples_bucket,
                object_name=f"{file_hash}.meta",
                data=io.BytesIO(
                    json.dumps(
                        {
                            "filename": filename,
                            "object_key": object_key,
                            "hash": file_hash,
                            "timestamp": datetime.utcnow().isoformat(),
                        }
                    ).encode("utf-8")
                ),
                length=-1,
                content_type="application/json",
            )

            logger.debug(
                f"Saved sample {filename} to MinIO bucket {self.samples_bucket}/{object_key} (hash: {file_hash})"
            )
            return f"{self.samples_bucket}/{object_key}", file_hash
        except S3Error as e:
            logger.error(f"Failed to save sample {filename} to MinIO: {str(e)}")
            raise StorageError(f"Failed to save sample to MinIO: {str(e)}")

    def get_sample(self, sample_id: str) -> bytes:
        """Get a sample from MinIO storage."""
        try:
            # Check if sample_id is a full object key
            if "/" in sample_id:
                bucket, _, object_key = sample_id.partition("/")
                if bucket == self.samples_bucket:
                    # Get object directly
                    response = self.client.get_object(bucket, object_key)
                    content = response.read()
                    response.close()
                    response.release_conn()
                    return content

            # Check if sample_id is a hash
            if len(sample_id) == 64:  # SHA-256 hash length
                # Try to get the metadata object
                try:
                    meta_response = self.client.get_object(
                        bucket_name=self.samples_bucket, object_name=f"{sample_id}.meta"
                    )
                    meta_content = meta_response.read().decode("utf-8")
                    meta_response.close()
                    meta_response.release_conn()

                    metadata = json.loads(meta_content)
                    object_key = metadata.get("object_key")

                    if object_key:
                        # Get the actual sample
                        sample_response = self.client.get_object(
                            bucket_name=self.samples_bucket, object_name=object_key
                        )
                        content = sample_response.read()
                        sample_response.close()
                        sample_response.release_conn()
                        return content
                except S3Error:
                    # Metadata not found, try direct hash directory structure
                    prefix = f"{sample_id[:2]}/{sample_id[2:4]}/"
                    objects = list(
                        self.client.list_objects(
                            bucket_name=self.samples_bucket, prefix=prefix, recursive=False
                        )
                    )

                    if objects:
                        # Get the first object in the hash directory
                        sample_response = self.client.get_object(
                            bucket_name=self.samples_bucket, object_name=objects[0].object_name
                        )
                        content = sample_response.read()
                        sample_response.close()
                        sample_response.release_conn()
                        return content

            raise StorageError(f"Sample not found: {sample_id}")
        except S3Error as e:
            logger.error(f"Failed to get sample {sample_id} from MinIO: {str(e)}")
            raise StorageError(f"Failed to get sample from MinIO: {str(e)}")

    def save_result(self, result_id: str, content: Dict[str, Any]) -> str:
        """Save a scan result to MinIO storage."""
        # Ensure the result ID is valid for an object key
        safe_id = result_id.replace("/", "_").replace("\\", "_")
        object_key = f"{safe_id}.json"

        # Convert content to JSON
        content_json = json.dumps(content, indent=2, default=str)
        content_bytes = content_json.encode("utf-8")

        try:
            # Upload the result to MinIO
            self.client.put_object(
                bucket_name=self.results_bucket,
                object_name=object_key,
                data=io.BytesIO(content_bytes),
                length=len(content_bytes),
                content_type="application/json",
            )

            logger.debug(
                f"Saved result {result_id} to MinIO bucket {self.results_bucket}/{object_key}"
            )
            return f"{self.results_bucket}/{object_key}"
        except S3Error as e:
            logger.error(f"Failed to save result {result_id} to MinIO: {str(e)}")
            raise StorageError(f"Failed to save result to MinIO: {str(e)}")

    def get_result(self, result_id: str) -> Dict[str, Any]:
        """Get a scan result from MinIO storage."""
        try:
            # Check if result_id is a full object key
            if "/" in result_id:
                bucket, _, object_key = result_id.partition("/")
                if bucket == self.results_bucket:
                    # Get object directly
                    response = self.client.get_object(bucket, object_key)
                    content_json = response.read().decode("utf-8")
                    response.close()
                    response.release_conn()
                    return json.loads(content_json)

            # Ensure the result ID is valid for an object key
            safe_id = result_id.replace("/", "_").replace("\\", "_")
            object_key = f"{safe_id}.json"

            # Get the result from MinIO
            response = self.client.get_object(
                bucket_name=self.results_bucket, object_name=object_key
            )

            # Read the content and decode
            content_json = response.read().decode("utf-8")
            response.close()
            response.release_conn()

            return json.loads(content_json)
        except S3Error as e:
            logger.error(f"Failed to get result {result_id} from MinIO: {str(e)}")
            raise StorageError(f"Result not found or error accessing result: {str(e)}")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse result {result_id} from MinIO: {str(e)}")
            raise StorageError(f"Failed to parse result JSON: {str(e)}")


# This function must be defined AFTER the class definitions above
def get_storage_client() -> StorageClient:
    """Get the appropriate storage client based on configuration."""
    if settings.USE_MINIO:
        try:
            return MinioStorageClient()
        except (ImportError, ValueError) as e:
            logger.warning(f"Failed to initialize MinIO storage: {str(e)}")
            logger.warning("Falling back to local storage")
            return LocalStorageClient()
        except Exception as e:
            logger.warning(f"Unexpected error initializing MinIO storage: {str(e)}")
            logger.warning("Falling back to local storage")
            return LocalStorageClient()
    else:
        return LocalStorageClient()
