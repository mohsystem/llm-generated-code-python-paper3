import os
import sys
import time
import tempfile
import shutil
from pathlib import Path
from typing import Optional

BUFFER_SIZE = 8192
TEMP_PREFIX = "secure_temp_"

def copy_file_to_temp(source_file_path: str) -> str:
    """
    Securely copy a file to a temporary location with proper error handling.

    Args:
        source_file_path: Path to the source file

    Returns:
        Path to the temporary file

    Raises:
        ValueError: If input is invalid
        FileNotFoundError: If source file doesn't exist
        IOError: If file operations fail
    """
    # Validate input
    if not source_file_path or not source_file_path.strip():
        raise ValueError("Source file path cannot be None or empty")

    try:
        # Normalize and resolve path to prevent traversal attacks
        source_path = Path(source_file_path).resolve()

        # Check if file exists
        if not source_path.exists():
            raise FileNotFoundError(f"Source file does not exist: {source_path}")

        # Check if it's a regular file
        if not source_path.is_file():
            raise ValueError(f"Source path is not a regular file: {source_path}")

        # Check if file is readable
        if not os.access(source_path, os.R_OK):
            raise IOError(f"Source file is not readable: {source_path}")

        # Create secure temporary file
        temp_fd, temp_path = tempfile.mkstemp(prefix=TEMP_PREFIX, suffix=".tmp")

        try:
            # Close the file descriptor as we'll use higher-level operations
            os.close(temp_fd)

            # Copy file content securely
            with open(source_path, 'rb') as src_file:
                with open(temp_path, 'wb') as temp_file:
                    while True:
                        chunk = src_file.read(BUFFER_SIZE)
                        if not chunk:
                            break
                        temp_file.write(chunk)

            return temp_path

        except Exception as e:
            # Clean up temporary file on error
            try:
                os.remove(temp_path)
            except OSError:
                pass
            raise IOError(f"Error copying file to temporary location: {str(e)}") from e

    except (ValueError, FileNotFoundError, IOError):
        raise
    except Exception as e:
        raise IOError(f"Unexpected error: {str(e)}") from e


def main():
    """Test cases for the file copy function."""

    # Test case 1: Valid file
    print("Test 1: Valid file")
    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("Test content 1")
            test_file1 = f.name

        result = copy_file_to_temp(test_file1)
        print(f"Success: Copied to {result}")
        os.remove(test_file1)
        os.remove(result)
    except Exception as e:
        print(f"Error: {e}")

    # Test case 2: Non-existent file
    print("\nTest 2: Non-existent file")
    try:
        copy_file_to_temp("/non/existent/file.txt")
    except Exception as e:
        print(f"Expected error: {e}")

    # Test case 3: None input
    print("\nTest 3: None input")
    try:
        copy_file_to_temp(None)  # type: ignore[arg-type]
    except Exception as e:
        print(f"Expected error: {e}")

    # Test case 4: Empty string
    print("\nTest 4: Empty string")
    try:
        copy_file_to_temp("")
    except Exception as e:
        print(f"Expected error: {e}")

    # Test case 5: Large file
    print("\nTest 5: Large file")
    try:
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.txt') as f:
            f.write(os.urandom(100000))
            test_file5 = f.name

        result = copy_file_to_temp(test_file5)
        print(f"Success: Large file copied to {result}")
        os.remove(test_file5)
        os.remove(result)
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
