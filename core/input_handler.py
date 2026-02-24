"""
Module 1 — Input Handler
Accepts configuration file paths, validates existence/readability,
computes SHA-256 hash, reads content, and returns ConfigInput objects.
"""

import os
import hashlib
from typing import Optional, Tuple, List, Dict
from datetime import datetime
from core.models import ConfigInput  # pyre-ignore


class InputHandler:
    """Handles file input validation, reading, and hashing."""

    SUPPORTED_EXTENSIONS = {
        '.conf', '.cfg', '.config', '.txt', '.ini',
        '.junos', '.rules', '.htaccess', '.xml',
        '.yaml', '.yml', '.properties'
    }

    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB limit

    def __init__(self, max_file_size: Optional[int] = None):
        if max_file_size:
            self.MAX_FILE_SIZE = max_file_size

    def load_file(self, file_path: str) -> ConfigInput:
        """
        Load and validate a configuration file.

        Args:
            file_path: Path to the configuration file.

        Returns:
            ConfigInput object with file content and metadata.

        Raises:
            FileNotFoundError: If file does not exist.
            PermissionError: If file is not readable.
            ValueError: If file is empty, too large, or binary.
        """
        # Normalize path
        file_path = os.path.abspath(file_path)

        # Check existence
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Configuration file not found: {file_path}")

        # Check it's a file (not directory)
        if not os.path.isfile(file_path):
            raise ValueError(f"Path is not a file: {file_path}")

        # Check readability
        if not os.access(file_path, os.R_OK):
            raise PermissionError(f"File is not readable: {file_path}")

        # Check file size
        file_size = os.path.getsize(file_path)
        if file_size == 0:
            raise ValueError(f"Configuration file is empty: {file_path}")
        if file_size > self.MAX_FILE_SIZE:
            raise ValueError(
                f"File exceeds maximum size ({self.MAX_FILE_SIZE} bytes): {file_path}"
            )

        # Read content
        try:
            with open(file_path, 'r', encoding='utf-8', errors='strict') as f:
                content = f.read()
        except UnicodeDecodeError:
            raise ValueError(
                f"File appears to be binary or uses unsupported encoding: {file_path}"
            )

        # Compute SHA-256 hash
        file_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()

        return ConfigInput(
            path=file_path,
            content=content,
            file_hash=file_hash,
            file_size=file_size,
            timestamp=datetime.now().isoformat(),
            filename=os.path.basename(file_path)
        )

    def load_directory(self, dir_path: str) -> Tuple[List[ConfigInput], List[Dict[str, str]]]:
        """
        Load all configuration files from a directory.

        Args:
            dir_path: Path to directory containing config files.

        Returns:
            List of ConfigInput objects.
        """
        dir_path = os.path.abspath(dir_path)

        if not os.path.isdir(dir_path):
            raise NotADirectoryError(f"Not a directory: {dir_path}")

        results = []
        errors = []

        for filename in sorted(os.listdir(dir_path)):
            file_path = os.path.join(dir_path, filename)
            if not os.path.isfile(file_path):
                continue

            _, ext = os.path.splitext(filename)
            if ext.lower() not in self.SUPPORTED_EXTENSIONS:
                continue

            try:
                config_input = self.load_file(file_path)
                results.append(config_input)
            except (ValueError, PermissionError) as e:
                errors.append({"file": file_path, "error": str(e)})

        return results, errors
