"""
Recursive directory scanner for discovering supported files, enforcing max size limits, skipping binary files, and detecting secrets.
"""

import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Callable, Optional, Set

from secretscan.detector import SecretDetector, SecretMatch
from secretscan.utils import (
    is_ignored_directory,
    is_supported_file,
    read_file_lines,
    load_secretscanignore,
    is_binary_file,
    is_file_too_large,
    DEFAULT_IGNORED_DIRS,
    DEFAULT_SUPPORTED_EXTENSIONS
)


@dataclass
class ScanResult:
    """Summary and findings of a scan operation."""
    target_path: str
    files_scanned: int = 0
    lines_scanned: int = 0
    duration_seconds: float = 0.0
    matches: List[SecretMatch] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class DirectoryScanner:
    """Traverses directories, reads supported text files, and delegates line detection."""

    def __init__(
        self,
        detector: Optional[SecretDetector] = None,
        ignored_dirs: Optional[Set[str]] = None,
        supported_exts: Optional[Set[str]] = None,
        max_file_size_bytes: int = 5 * 1024 * 1024
    ):
        self.detector = detector or SecretDetector()
        self.ignored_dirs = set(ignored_dirs) if ignored_dirs is not None else set(DEFAULT_IGNORED_DIRS)
        self.supported_exts = supported_exts or DEFAULT_SUPPORTED_EXTENSIONS
        self.max_file_size_bytes = max_file_size_bytes

    def scan_directory(
        self,
        target_path: str,
        progress_callback: Optional[Callable[[str, int], None]] = None
    ) -> ScanResult:
        """
        Recursively scans the target directory for secrets.
        """
        abs_target = os.path.abspath(target_path)
        result = ScanResult(target_path=target_path)
        start_time = time.time()

        if not os.path.exists(abs_target):
            result.errors.append(f"Target path does not exist: {target_path}")
            return result

        # Load .secretscanignore if scanning a directory
        if os.path.isdir(abs_target):
            custom_ignores = load_secretscanignore(abs_target)
            self.ignored_dirs.update(custom_ignores)

        # Handle scanning a single file directly
        if os.path.isfile(abs_target):
            self._scan_single_file(abs_target, target_path, result)
            result.duration_seconds = round(time.time() - start_time, 3)
            return result

        # Walk directory tree
        for root, dirs, files in os.walk(abs_target):
            # Exclude ignored directories in-place so os.walk skips them
            dirs[:] = [d for d in dirs if not is_ignored_directory(d, self.ignored_dirs)]

            for file_name in files:
                if file_name in self.ignored_dirs or file_name.startswith(".secretscanignore"):
                    continue

                full_path = os.path.join(root, file_name)
                rel_path = os.path.relpath(full_path, start=abs_target)

                if is_supported_file(full_path, self.supported_exts):
                    self._scan_single_file(full_path, rel_path, result)
                    if progress_callback:
                        progress_callback(rel_path, result.files_scanned)

        result.duration_seconds = round(time.time() - start_time, 3)
        return result

    def _scan_single_file(self, full_path: str, display_path: str, result: ScanResult) -> None:
        # Check max file size
        if is_file_too_large(full_path, self.max_file_size_bytes):
            result.errors.append(f"Skipped large file (>{self.max_file_size_bytes // (1024*1024)}MB): {display_path}")
            return

        # Check binary file
        if is_binary_file(full_path):
            return

        lines, error = read_file_lines(full_path)
        if error:
            result.errors.append(error)
            return

        result.files_scanned += 1
        result.lines_scanned += len(lines)

        for line_idx, line in enumerate(lines, start=1):
            matches = self.detector.scan_line(line, line_idx, display_path)
            result.matches.extend(matches)
