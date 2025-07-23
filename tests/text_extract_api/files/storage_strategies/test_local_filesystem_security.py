import os
import tempfile
import pytest

from text_extract_api.files.storage_strategies.local_filesystem import LocalFilesystemStorageStrategy


def test_path_traversal_protection():
    """Test that path traversal attacks are blocked"""
    with tempfile.TemporaryDirectory() as temp_dir:
        context = {
            'settings': {
                'root_path': temp_dir,
                'create_subfolders': False,
                'subfolder_names_format': ''
            }
        }
        storage = LocalFilesystemStorageStrategy(context)
        
        # Test path traversal attempts
        malicious_filenames = [
            "../../../../../../etc/passwd",
            "../../../secret.txt",
            "..\\..\\..\\secret.txt",
            "file/../../../etc/passwd"
        ]
        
        for filename in malicious_filenames:
            with pytest.raises(ValueError, match="Path traversal detected"):
                storage.load(filename)
            
            with pytest.raises(ValueError, match="Path traversal detected"):
                storage.save("test.txt", filename, "content")
            
            with pytest.raises(ValueError, match="Path traversal detected"):
                storage.delete(filename)


def test_legitimate_operations():
    """Test that legitimate file operations work correctly"""
    with tempfile.TemporaryDirectory() as temp_dir:
        context = {
            'settings': {
                'root_path': temp_dir,
                'create_subfolders': False,
                'subfolder_names_format': ''
            }
        }
        storage = LocalFilesystemStorageStrategy(context)
        
        # Test normal file operations
        filename = "test.txt"
        content = "Test content"
        
        # Save file
        storage.save(filename, filename, content)
        
        # Load file
        loaded_content = storage.load(filename)
        assert loaded_content == content
        
        # List files
        files = storage.list()
        assert filename in files
        
        # Delete file
        storage.delete(filename)
        
        # Verify file is deleted
        with pytest.raises(FileNotFoundError):
            storage.load(filename)


def test_absolute_path_protection():
    """Test that absolute paths are blocked"""
    with tempfile.TemporaryDirectory() as temp_dir:
        context = {
            'settings': {
                'root_path': temp_dir,
                'create_subfolders': False,
                'subfolder_names_format': ''
            }
        }
        storage = LocalFilesystemStorageStrategy(context)
        
        # Test absolute path attempts
        malicious_filenames = [
            "/etc/passwd",
            "/tmp/malicious.txt",
            "C:\\Windows\\System32\\config\\SAM"
        ]
        
        for filename in malicious_filenames:
            with pytest.raises(ValueError, match="Path traversal detected"):
                storage.load(filename)
            
            with pytest.raises(ValueError, match="Path traversal detected"):
                storage.save("test.txt", filename, "content")
            
            with pytest.raises(ValueError, match="Path traversal detected"):
                storage.delete(filename)


def test_backslash_protection():
    """Test that Windows-style path separators are blocked"""
    with tempfile.TemporaryDirectory() as temp_dir:
        context = {
            'settings': {
                'root_path': temp_dir,
                'create_subfolders': False,
                'subfolder_names_format': ''
            }
        }
        storage = LocalFilesystemStorageStrategy(context)
        
        # Test backslash attempts
        malicious_filenames = [
            "..\\..\\secret.txt",
            "file\\..\\..\\secret.txt",
            "normal\\path\\file.txt"  # This should also be blocked for security
        ]
        
        for filename in malicious_filenames:
            with pytest.raises(ValueError, match="Path traversal detected"):
                storage.load(filename)
            
            with pytest.raises(ValueError, match="Path traversal detected"):
                storage.save("test.txt", filename, "content")
            
            with pytest.raises(ValueError, match="Path traversal detected"):
                storage.delete(filename)