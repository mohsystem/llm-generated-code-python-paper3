
import os
import hashlib
import time
import re
from pathlib import Path
from typing import Tuple, Optional

class Task50:
    UPLOAD_DIR = "uploads"
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'jpg', 'jpeg', 'png', 'gif', 'doc', 'docx'}
    SAFE_FILENAME_PATTERN = re.compile(r'^[a-zA-Z0-9._-]+$')

    @staticmethod
    def upload_file(filename: str, file_content: bytes) -> Tuple[bool, str, Optional[str]]:
        """\n        Securely upload a file to the server.\n        \n        Args:\n            filename: Original filename\n            file_content: File content as bytes\n            \n        Returns:\n            Tuple of (success, message, saved_path)\n        """
        try:
            # Validate filename
            if not filename or not filename.strip():
                return False, "Invalid filename", None

            # Sanitize filename - remove path components
            sanitized_filename = os.path.basename(filename)
            
            # Additional filename validation
            if not Task50.SAFE_FILENAME_PATTERN.match(sanitized_filename):
                sanitized_filename = re.sub(r'[^a-zA-Z0-9._-]', '_', sanitized_filename)

            # Validate file extension
            extension = Task50._get_file_extension(sanitized_filename)
            if extension.lower() not in Task50.ALLOWED_EXTENSIONS:
                return False, f"File type not allowed: {extension}", None

            # Validate file size
            if file_content is None or len(file_content) == 0:
                return False, "Empty file content", None
            if len(file_content) > Task50.MAX_FILE_SIZE:
                return False, "File size exceeds maximum limit", None

            # Create upload directory if it doesn't exist\n            upload_path = Path(Task50.UPLOAD_DIR)\n            upload_path.mkdir(parents=True, exist_ok=True)\n\n            # Generate unique filename\n            unique_filename = Task50._generate_unique_filename(sanitized_filename)\n            target_path = upload_path / unique_filename\n\n            # Prevent path traversal\n            target_path = target_path.resolve()\n            if not str(target_path).startswith(str(upload_path.resolve())):\n                return False, "Invalid file path detected", None\n\n            # Write file securely\n            with open(target_path, 'wb') as f:\n                f.write(file_content)\n\n            # Set file permissions (read/write for owner only)\n            try:\n                os.chmod(target_path, 0o600)\n            except:\n                pass  # Windows doesn't support chmod

            return True, f"File uploaded successfully: {unique_filename}", str(target_path)

        except Exception as e:
            return False, f"Upload failed: {str(e)}", None

    @staticmethod
    def _get_file_extension(filename: str) -> str:
        """Extract file extension from filename."""
        parts = filename.rsplit('.', 1)
        return parts[1] if len(parts) > 1 else ""

    @staticmethod
    def _generate_unique_filename(original_filename: str) -> str:
        """Generate a unique filename to prevent overwriting."""
        timestamp = str(int(time.time() * 1000))
        name_parts = original_filename.rsplit('.', 1)
        name_without_ext = name_parts[0]
        extension = name_parts[1] if len(name_parts) > 1 else ""
        
        unique_name = f"{name_without_ext}_{timestamp}"
        if extension:
            unique_name += f".{extension}"
        
        return unique_name


def main():
    print("=== Secure File Upload Server - Test Cases ===\\n")

    # Test Case 1: Valid text file upload
    test_content1 = b"This is a test file content."
    success1, message1, path1 = Task50.upload_file("test_document.txt", test_content1)
    print("Test 1 - Valid text file:")
    print(f"Success: {success1}")
    print(f"Message: {message1}\\n")

    # Test Case 2: Valid PDF file upload
    test_content2 = b'A' * 1024
    success2, message2, path2 = Task50.upload_file("report.pdf", test_content2)
    print("Test 2 - Valid PDF file:")
    print(f"Success: {success2}")
    print(f"Message: {message2}\\n")

    # Test Case 3: Invalid file extension
    success3, message3, path3 = Task50.upload_file("malicious.exe", b"malware")
    print("Test 3 - Invalid extension (.exe):")
    print(f"Success: {success3}")
    print(f"Message: {message3}\\n")

    # Test Case 4: Path traversal attempt
    success4, message4, path4 = Task50.upload_file("../../etc/passwd.txt", b"hack")
    print("Test 4 - Path traversal attempt:")
    print(f"Success: {success4}")
    print(f"Message: {message4}\\n")

    # Test Case 5: Empty file
    success5, message5, path5 = Task50.upload_file("empty.txt", b"")
    print("Test 5 - Empty file:")
    print(f"Success: {success5}")
    print(f"Message: {message5}\\n")


if __name__ == "__main__":
    main()
