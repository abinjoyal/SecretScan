"""
Unit tests for SecretScan scanner module.
"""

import os
import tempfile
import pytest
from secretscan.scanner import DirectoryScanner
from secretscan.detector import SecretDetector
from secretscan.utils import (
    is_ignored_directory,
    is_supported_file,
    mask_secret,
    is_binary_file,
    is_file_too_large
)


def test_is_ignored_directory():
    assert is_ignored_directory(".git") is True
    assert is_ignored_directory("venv") is True
    assert is_ignored_directory(".venv") is True
    assert is_ignored_directory("node_modules") is True
    assert is_ignored_directory("src") is False


def test_is_supported_file():
    assert is_supported_file("script.py") is True
    assert is_supported_file("app.js") is True
    assert is_supported_file(".env") is True
    assert is_supported_file("config.yaml") is True
    assert is_supported_file("image.png") is False
    assert is_supported_file("document.pdf") is False


def test_mask_secret():
    assert mask_secret("123") == "***"
    assert mask_secret("secret123") == "se****123"
    assert mask_secret("sk-1234567890abcdef1234567890") == "sk****890"


def test_directory_scan():
    with tempfile.TemporaryDirectory() as tmp_dir:
        # Create a clean file
        clean_file = os.path.join(tmp_dir, "clean.py")
        with open(clean_file, "w", encoding="utf-8") as f:
            f.write("def hello():\n    print('Hello world')\n")

        # Create a file with a synthetic secret
        dirty_file = os.path.join(tmp_dir, "dirty.py")
        with open(dirty_file, "w", encoding="utf-8") as f:
            f.write("API_KEY = 'sk-1234567890abcdef1234567890abcdef'\n")

        # Create an ignored directory with a secret file (should be skipped)
        venv_dir = os.path.join(tmp_dir, "venv")
        os.makedirs(venv_dir)
        ignored_file = os.path.join(venv_dir, "ignored.py")
        with open(ignored_file, "w", encoding="utf-8") as f:
            f.write("PASSWORD = 'my_super_secret_password_123'\n")

        scanner = DirectoryScanner(ignored_dirs={".git", "venv"})
        result = scanner.scan_directory(tmp_dir)

        assert result.files_scanned == 2  # clean.py and dirty.py (venv ignored)
        assert len(result.matches) >= 1
        assert any(m.secret_type == "OpenAI API Key" for m in result.matches)


def test_secretscanignore_file():
    with tempfile.TemporaryDirectory() as tmp_dir:
        # Create .secretscanignore
        ignore_path = os.path.join(tmp_dir, ".secretscanignore")
        with open(ignore_path, "w", encoding="utf-8") as f:
            f.write("ignore_folder/\n")

        # Create ignored folder
        ignored_folder = os.path.join(tmp_dir, "ignore_folder")
        os.makedirs(ignored_folder)
        ignored_file = os.path.join(ignored_folder, "secret.py")
        with open(ignored_file, "w", encoding="utf-8") as f:
            f.write("API_KEY = 'sk-1234567890abcdef1234567890abcdef'\n")

        scanner = DirectoryScanner()
        result = scanner.scan_directory(tmp_dir)

        assert result.files_scanned == 0
        assert len(result.matches) == 0


def test_binary_file_skipping():
    with tempfile.TemporaryDirectory() as tmp_dir:
        bin_file = os.path.join(tmp_dir, "binary_data.py")
        with open(bin_file, "wb") as f:
            f.write(b"API_KEY = 'sk-1234567890'\x00\x01\x02\x03")

        assert is_binary_file(bin_file) is True
        scanner = DirectoryScanner()
        result = scanner.scan_directory(tmp_dir)
        assert len(result.matches) == 0
