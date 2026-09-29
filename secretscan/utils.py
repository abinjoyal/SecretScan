"""
Utility functions for file filtering, path handling, masking, binary checks, and .secretscanignore loading.
"""

import os
from pathlib import Path
from typing import List, Tuple, Optional, Set

DEFAULT_IGNORED_DIRS: Set[str] = {
    ".git",
    "venv",
    ".venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".idea",
    ".vscode",
    "build",
    "dist",
    "eggs",
    "reports",
    "tests",
    "test",
}

DEFAULT_SUPPORTED_EXTENSIONS: Set[str] = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".json",
    ".yaml",
    ".yml",
    ".env",
    ".ini",
    ".config",
    ".toml",
    ".xml",
    ".conf",
}

DEFAULT_SUPPORTED_FILENAMES: Set[str] = {
    ".env",
    ".env.local",
    ".env.development",
    ".env.production",
    "config",
}


def load_secretscanignore(target_dir: str) -> Set[str]:
    """
    Parses a .secretscanignore file if present in the target directory.
    Returns a set of directory/file names to ignore.
    """
    ignore_path = os.path.join(target_dir, ".secretscanignore")
    ignored_items: Set[str] = set()

    if not os.path.isfile(ignore_path):
        return ignored_items

    try:
        with open(ignore_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Strip trailing slashes
                clean_item = line.rstrip("/")
                ignored_items.add(clean_item)
    except Exception:
        pass

    return ignored_items


def is_binary_file(file_path: str) -> bool:
    """
    Checks if a file is binary by inspecting its first 1024 bytes for null bytes.
    """
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(1024)
            if b"\x00" in chunk:
                return True
    except Exception:
        return False
    return False


def is_file_too_large(file_path: str, max_bytes: int = 5 * 1024 * 1024) -> bool:
    """
    Checks if file size exceeds max allowed size in bytes (default: 5MB).
    """
    try:
        return os.path.getsize(file_path) > max_bytes
    except Exception:
        return False


def is_ignored_directory(dir_name: str, custom_ignored: Optional[Set[str]] = None) -> bool:
    """Check if a directory name should be skipped during scanning."""
    ignored = custom_ignored if custom_ignored is not None else DEFAULT_IGNORED_DIRS
    return dir_name in ignored or dir_name.endswith(".egg-info")


def is_supported_file(
    file_path: str,
    supported_extensions: Optional[Set[str]] = None,
    supported_filenames: Optional[Set[str]] = None,
) -> bool:
    """Determine whether a file should be scanned based on extension or exact filename."""
    exts = supported_extensions if supported_extensions is not None else DEFAULT_SUPPORTED_EXTENSIONS
    names = supported_filenames if supported_filenames is not None else DEFAULT_SUPPORTED_FILENAMES

    path = Path(file_path)
    file_name = path.name

    if file_name in names or file_name.lower() in names:
        return True

    return path.suffix.lower() in exts


def mask_secret(secret_value: str) -> str:
    """
    Safely mask secret strings so secrets are never displayed in full.
    """
    if not secret_value:
        return "****"

    clean_value = secret_value.strip()
    length = len(clean_value)

    if length <= 4:
        return "*" * length
    elif length <= 8:
        return f"{clean_value[0]}*{'*' * (length - 2)}{clean_value[-1]}"
    else:
        prefix = clean_value[:2]
        suffix = clean_value[-3:]
        masked_middle = "*" * 4
        return f"{prefix}{masked_middle}{suffix}"


def read_file_lines(file_path: str) -> Tuple[List[str], Optional[str]]:
    """
    Safely read file lines with encoding fallbacks and error handling.
    """
    encodings = ["utf-8", "latin-1", "cp1252"]

    for encoding in encodings:
        try:
            with open(file_path, "r", encoding=encoding, errors="replace") as f:
                return f.readlines(), None
        except UnicodeDecodeError:
            continue
        except PermissionError:
            return [], f"Permission denied: unable to read {file_path}"
        except FileNotFoundError:
            return [], f"File not found: {file_path}"
        except Exception as err:
            return [], f"Error reading {file_path}: {str(err)}"

    return [], f"Failed to decode file contents for {file_path}"
