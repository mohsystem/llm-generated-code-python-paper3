
import os
import hashlib
import re
from pathlib import Path
from typing import Tuple, Optional

class Task121:
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'jpg', 'jpeg', 'png', 'doc', 'docx'}
    UPLOAD_DIR = 'uploads'
    SAFE_FILENAME_PATTERN = re.compile(r'^[a-zA-Z0-9_\\-\\.]+$')

@staticmethod
def upload_file(original_filename: str, file_content: bytes) -> Tuple[bool, str, Optional[str]]:
    """Upload a file securely with validation
    Returns: (success, message, saved_path)
    """
    try:
        # Validate filename is not None or empty
        if not original_filename or not original_filename.strip():
            return False, "Filename cannot be empty", None

        # Validate file content is not None or empty
        if file_content is None or len(file_content) == 0:
            return False, "File content cannot be empty", None

        # Check file size
        if len(file_content) > Task121.MAX_FILE_SIZE:
            return False, "File size exceeds maximum limit of 10MB", None

        # Sanitize filename - remove path traversal attempts
        sanitized_filename = os.path.basename(original_filename)

        # Validate filename pattern
        if not Task121.SAFE_FILENAME_PATTERN.match(sanitized_filename):
            return False, "Invalid filename. Use only alphanumeric characters, hyphens, underscores, and dots", None

        # Validate file extension
        extension = Task121._get_file_extension(sanitized_filename).lower()
        if extension not in Task121.ALLOWED_EXTENSIONS:
            return False, f"File type not allowed. Allowed types: {Task121.ALLOWED_EXTENSIONS}", None

        # Create upload directory if it doesn't exist
        os.makedirs(Task121.UPLOAD_DIR, mode=0o700, exist_ok=True)

        # Generate unique filename
        unique_filename = Task121._generate_unique_filename(sanitized_filename)

        # Construct safe file path
        upload_path = Path(Task121.UPLOAD_DIR) / unique_filename
        upload_path = upload_path.resolve()

        # Verify the path is within upload directory (prevent path traversal)
        upload_dir_abs = Path(Task121.UPLOAD_DIR).resolve()
        if not str(upload_path).startswith(str(upload_dir_abs)):
            return False, "Invalid upload path", None

        # Check if file already exists
        if upload_path.exists():
            return False, "File already exists", None

        # Write file securely with restricted permissions
        upload_path.touch(mode=0o600)
        upload_path.write_bytes(file_content)

        return True, "File uploaded successfully", str(upload_path)

    except PermissionError:
        return False, "Permission denied", None
    except OSError as e:
        return False, f"Error writing file: {str(e)}", None
    except Exception as e:
        return False, f"Unexpected error: {str(e)}", None


@staticmethod
def _get_file_extension(filename: str) -> str:
    """Extract file extension safely"""
    if '.' not in filename:
        return ""
    return filename.rsplit('.', 1)[-1]


@staticmethod
def _generate_unique_filename(original_filename: str) -> str:
    """Generate unique filename using timestamp and hash"""
    try:
        import time
        timestamp = str(int(time.time() * 1000))
        base_name = original_filename.rsplit('.', 1)[0]
        extension = Task121._get_file_extension(original_filename)

        hash_input = (base_name + timestamp).encode('utf-8')
        hash_str = hashlib.sha256(hash_input).hexdigest()[:8]

        return f"{base_name}_{timestamp}_{hash_str}.{extension}"
    except Exception:
        return original_filename.replace('.', f'_{int(time.time() * 1000)}.', 1)


def main():
    print("=== File Upload Program Test Cases ===\\n")
    
    # Test Case 1: Valid text file upload
    print("Test 1: Valid text file upload")
    content1 = b"Hello, this is a test file content."
    success1, message1, path1 = Task121.upload_file("test_document.txt", content1)
    print(f"Success: {success1}")
    print(f"Message: {message1}")
    print(f"Path: {path1}\\n")
    
    # Test Case 2: Invalid file extension
    print("Test 2: Invalid file extension (.exe)")
    content2 = b"Malicious content"
    success2, message2, path2 = Task121.upload_file("malware.exe", content2)
    print(f"Success: {success2}")
    print(f"Message: {message2}\\n")
    
    # Test Case 3: Path traversal attempt
    print("Test 3: Path traversal attempt")
    content3 = b"Attack content"
    success3, message3, path3 = Task121.upload_file("../../etc/passwd.txt", content3)
    print(f"Success: {success3}")
    print(f"Message: {message3}\\n")
    
    # Test Case 4: Empty filename
    print("Test 4: Empty filename")
    content4 = b"Some content"
    success4, message4, path4 = Task121.upload_file("", content4)
    print(f"Success: {success4}")
    print(f"Message: {message4}\\n")
    
    # Test Case 5: File size exceeds limit
    print("Test 5: File size exceeds limit")
    content5 = b"A" * (Task121.MAX_FILE_SIZE + 1)
    success5, message5, path5 = Task121.upload_file("large_file.txt", content5)
    print(f"Success: {success5}")
    print(f"Message: {message5}\\n")


if __name__ == "__main__":
    main()
