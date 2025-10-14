
import os
import re
import secrets
from pathlib import Path
from typing import Optional, Tuple
from dataclasses import dataclass

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
ALLOWED_EXTENSIONS = {'.txt', '.pdf', '.jpg', '.jpeg', '.png', '.gif', '.doc', '.docx'}
SAFE_FILENAME_PATTERN = re.compile(r'^[a-zA-Z0-9_\\-\\.]+$')
UPLOAD_BASE_DIR = 'uploads'


@dataclass
class UploadResult:
    success: bool
    message: str
    saved_path: Optional[str] = None


def sanitize_filename(filename: str) -> Optional[str]:
    """Sanitize filename to prevent path traversal and injection attacks."""
    if not filename or not filename.strip():
        return None
    
    # Extract just the filename, removing any path components
    name = os.path.basename(filename)
    
    # Replace unsafe characters with underscore
    name = re.sub(r'[^a-zA-Z0-9_\\-\\.]', '_', name)
    
    # Limit length
    if len(name) > 255:
        name = name[:255]
    
    # Validate against safe pattern
    if not SAFE_FILENAME_PATTERN.match(name):
        return None
    
    return name


def get_file_extension(filename: str) -> str:
    """Get file extension safely."""
    parts = filename.rsplit('.', 1)
    if len(parts) == 2:
        return '.' + parts[1]
    return ''


def generate_unique_filename(original_filename: str) -> str:
    """Generate a unique filename using secure random bytes."""
    extension = get_file_extension(original_filename)
    base_name = original_filename[:len(original_filename) - len(extension)] if extension else original_filename
    
    # Generate secure random token
    random_token = secrets.token_hex(16)
    
    return f"{base_name}_{random_token}{extension}"


def upload_file(original_filename: str, file_content: bytes) -> UploadResult:
    """\n    Upload a file with security validations.\n    \n    Args:\n        original_filename: The original name of the file\n        file_content: The binary content of the file\n    \n    Returns:\n        UploadResult with success status and message\n    """
    # Validate inputs
    if not original_filename or not original_filename.strip():
        return UploadResult(False, "Filename cannot be empty")
    
    if not file_content or len(file_content) == 0:
        return UploadResult(False, "File content cannot be empty")
    
    if len(file_content) > MAX_FILE_SIZE:
        return UploadResult(False, "File size exceeds maximum allowed size")
    
    # Sanitize filename
    sanitized_filename = sanitize_filename(original_filename)
    if not sanitized_filename:
        return UploadResult(False, "Invalid filename format")
    
    # Check file extension
    extension = get_file_extension(sanitized_filename).lower()
    if extension not in ALLOWED_EXTENSIONS:
        return UploadResult(False, "File type not allowed")
    
    try:
        # Create base directory with secure permissions
        base_dir = Path(UPLOAD_BASE_DIR).resolve()
        base_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        
        # Generate unique filename
        unique_filename = generate_unique_filename(sanitized_filename)
        target_path = (base_dir / unique_filename).resolve()
        
        # Validate path is within base directory (prevent path traversal)
        if not str(target_path).startswith(str(base_dir)):
            return UploadResult(False, "Invalid file path")
        
        # Check if file already exists
        if target_path.exists():
            return UploadResult(False, "File already exists")
        
        # Write to temporary file first, then atomic rename
        temp_file = base_dir / f"upload_{secrets.token_hex(8)}.tmp"
        try:
            with open(temp_file, 'wb') as f:
                f.write(file_content)
                f.flush()
                os.fsync(f.fileno())
            
            # Atomic rename
            temp_file.replace(target_path)
            
            # Set secure permissions (owner read/write only)
            try:
                os.chmod(target_path, 0o600)
            except (OSError, AttributeError):
                pass  # Some systems may not support this
            
            return UploadResult(True, "File uploaded successfully", str(target_path))
            
        except Exception as e:
            # Clean up temp file on error
            if temp_file.exists():
                temp_file.unlink()
            raise
            
    except Exception as e:
        return UploadResult(False, f"Upload failed: {str(e)}")


def main() -> None:
    """Test the file upload functionality."""
    print("File Upload System Test Cases\\n")
    
    # Test case 1: Valid text file
    content1 = b"Hello, World!"
    result1 = upload_file("test_document.txt", content1)
    print(f"Test 1 - Valid text file: {result1.success} - {result1.message}")
    
    # Test case 2: Invalid extension
    content2 = b"Some content"
    result2 = upload_file("malicious.exe", content2)
    print(f"Test 2 - Invalid extension: {result2.success} - {result2.message}")
    
    # Test case 3: Empty filename
    content3 = b"Content"
    result3 = upload_file("", content3)
    print(f"Test 3 - Empty filename: {result3.success} - {result3.message}")
    
    # Test case 4: Path traversal attempt
    content4 = b"Malicious"
    result4 = upload_file("../../etc/passwd.txt", content4)
    print(f"Test 4 - Path traversal attempt: {result4.success} - {result4.message}")
    
    # Test case 5: Valid image file
    content5 = secrets.token_bytes(1024)
    result5 = upload_file("photo_2024.jpg", content5)
    print(f"Test 5 - Valid image file: {result5.success} - {result5.message}")


if __name__ == "__main__":
    main()
