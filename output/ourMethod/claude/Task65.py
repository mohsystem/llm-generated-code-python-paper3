
import os
import sys
from pathlib import Path
from typing import Optional

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit
MAX_FILENAME_LENGTH = 255


def read_file_securely(filename: str, base_directory: str) -> str:
    """\n    Securely read a file from the base directory.\n    \n    Args:\n        filename: The name of the file to read\n        base_directory: The base directory to restrict file access\n        \n    Returns:\n        The content of the file as a string\n        \n    Raises:\n        ValueError: If filename is invalid or file doesn't meet requirements\n        PermissionError: If file is not accessible\n        FileNotFoundError: If file doesn't exist\n    """
    if not filename or not isinstance(filename, str):
        raise ValueError("Filename must be a non-empty string")
    
    if len(filename) > MAX_FILENAME_LENGTH:
        raise ValueError("Filename exceeds maximum length")
    
    # Validate filename - reject control characters and path traversal
    if not is_valid_filename(filename):
        raise ValueError("Invalid filename format")
    
    try:
        # Resolve base directory to absolute path
        base_path = Path(base_directory).resolve(strict=True)
        
        # Resolve requested file path
        requested_path = (base_path / filename).resolve()
        
        # Ensure the resolved path is within the base directory
        if not str(requested_path).startswith(str(base_path) + os.sep):
            if requested_path != base_path:
                raise PermissionError("Path traversal attempt detected")
        
        # Check if path exists
        if not requested_path.exists():
            raise FileNotFoundError(f"File not found: {filename}")
        
        # Check if path is a regular file (not directory or symlink to outside)
        if not requested_path.is_file():
            raise ValueError("Path is not a regular file")
        
        # Verify symlink doesn't point outside base directory\n        if requested_path.is_symlink():\n            real_target = requested_path.resolve()\n            if not str(real_target).startswith(str(base_path) + os.sep):\n                raise PermissionError("Symlink points outside base directory")\n        \n        # Check file size\n        file_size = requested_path.stat().st_size\n        if file_size > MAX_FILE_SIZE:\n            raise ValueError("File size exceeds maximum allowed size")\n        \n        # Read file content\n        with open(requested_path, 'r', encoding='utf-8') as f:\n            content = f.read()\n        \n        return content\n        \n    except (OSError, IOError) as e:\n        raise RuntimeError(f"Error reading file: {str(e)}")\n\n\ndef is_valid_filename(filename: str) -> bool:\n    """Validate filename format to prevent security issues."""\n    if '\\0' in filename or '..' in filename:\n        return False\n    \n    # Check for control characters\n    for char in filename:\n        if ord(char) < 32:\n            return False\n    \n    # Reject absolute paths\n    if filename.startswith('/') or filename.startswith('\\'):\n        return False\n    \n    # Reject Windows drive letters\n    if len(filename) > 1 and filename[1] == ':':\n        return False\n    \n    return True\n\n\ndef main():\n    base_dir = os.path.join(os.getcwd(), 'testfiles')\n    \n    # Create test directory and files\n    try:\n        os.makedirs(base_dir, exist_ok=True)\n        \n        # Test case 1: Valid file\n        test_file1 = os.path.join(base_dir, 'test1.txt')\n        with open(test_file1, 'w', encoding='utf-8') as f:\n            f.write('Hello, World!')\n        \n        # Test case 2: Another valid file\n        test_file2 = os.path.join(base_dir, 'test2.txt')\n        with open(test_file2, 'w', encoding='utf-8') as f:\n            f.write('Test content 2')\n        \n        # Test case 3: File with subdirectory\n        subdir = os.path.join(base_dir, 'subdir')\n        os.makedirs(subdir, exist_ok=True)\n        test_file3 = os.path.join(subdir, 'test3.txt')\n        with open(test_file3, 'w', encoding='utf-8') as f:\n            f.write('Subdirectory content')\n        \n    except IOError as e:\n        print(f"Setup error: {e}", file=sys.stderr)\n        return\n    \n    # Test case 1: Valid file\n    print("Test 1 - Valid file:")\n    try:\n        content = read_file_securely('test1.txt', base_dir)\n        print(f"Success: {content}")\n    except Exception as e:\n        print(f"Error: {e}", file=sys.stderr)\n    \n    # Test case 2: Another valid file\n    print("\\nTest 2 - Another valid file:")\n    try:\n        content = read_file_securely('test2.txt', base_dir)\n        print(f"Success: {content}")\n    except Exception as e:\n        print(f"Error: {e}", file=sys.stderr)\n    \n    # Test case 3: Valid file in subdirectory\n    print("\\nTest 3 - File in subdirectory:")\n    try:\n        content = read_file_securely('subdir/test3.txt', base_dir)\n        print(f"Success: {content}")\n    except Exception as e:\n        print(f"Error: {e}", file=sys.stderr)\n    \n    # Test case 4: Path traversal attempt\n    print("\\nTest 4 - Path traversal attempt:")\n    try:\n        content = read_file_securely('../../../etc/passwd', base_dir)\n        print(f"Success: {content}")\n    except Exception as e:\n        print(f"Error (expected): {e}", file=sys.stderr)\n    \n    # Test case 5: Non-existent file\n    print("\\nTest 5 - Non-existent file:")\n    try:\n        content = read_file_securely('nonexistent.txt', base_dir)
        print(f"Success: {content}")
    except Exception as e:
        print(f"Error (expected): {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
