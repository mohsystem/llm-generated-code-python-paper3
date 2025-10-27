
import os
import hashlib
import re
import time
import uuid
from pathlib import Path
from typing import Optional, Set

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
ALLOWED_EXTENSIONS: Set[str] = {'txt', 'pdf', 'jpg', 'jpeg', 'png', 'gif', 'doc', 'docx'}
UPLOAD_DIR = 'uploads'

def sanitize_filename(filename: str) -> Optional[str]:
    """Sanitize filename to prevent path traversal and injection attacks."""
    if not filename or not filename.strip():
        return None
    
    # Remove path separators and special characters
    sanitized = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)
    # Remove path traversal attempts
    sanitized = sanitized.replace('..', '')
    
    return sanitized if sanitized else None

def get_file_extension(filename: str) -> str:
    """Extract file extension from filename."""
    parts = filename.rsplit('.', 1)
    return parts[1] if len(parts) > 1 else ''

def generate_secure_filename(original_filename: str) -> str:
    """Generate a secure filename using hash and timestamp."""
    try:
        timestamp = str(time.time())
        hash_input = f"{original_filename}{timestamp}".encode()
        hash_string = hashlib.sha256(hash_input).hexdigest()[:16]
        extension = get_file_extension(original_filename)
        return f"{hash_string}.{extension}"
    except Exception:
        return f"{uuid.uuid4()}.{get_file_extension(original_filename)}"

def handle_file_upload(filename: str, file_content: bytes) -> str:
    """Handle file upload with security validations."""
    try:
        # Validate file size
        if len(file_content) > MAX_FILE_SIZE:
            return "Error: File size exceeds limit"
        
        # Sanitize and validate filename
        sanitized_filename = sanitize_filename(filename)
        if not sanitized_filename:
            return "Error: Invalid filename"
        
        # Validate file extension
        extension = get_file_extension(sanitized_filename).lower()
        if extension not in ALLOWED_EXTENSIONS:
            return "Error: File type not allowed"
        
        # Create upload directory if not exists
        upload_path = Path(UPLOAD_DIR)
        upload_path.mkdir(parents=True, exist_ok=True)
        
        # Generate secure filename
        secure_filename = generate_secure_filename(sanitized_filename)
        file_path = upload_path / secure_filename
        
        # Prevent path traversal
        if not file_path.resolve().is_relative_to(upload_path.resolve()):
            return "Error: Invalid file path"
        
        # Write file
        file_path.write_bytes(file_content)
        return f"Success: File uploaded as {secure_filename}"
        
    except Exception as e:
        return f"Error: {str(e)}"

def main():
    """Test cases for file upload functionality."""
    print("=== File Upload Security Test Cases ===\\n")
    
    # Test Case 1: Valid text file
    content1 = b"Hello, World!"
    print(f"Test 1 - Valid txt file: {handle_file_upload('document.txt', content1)}")
    
    # Test Case 2: Valid PDF file
    content2 = b"%PDF-1.4"
    print(f"Test 2 - Valid pdf file: {handle_file_upload('report.pdf', content2)}")
    
    # Test Case 3: Invalid file extension
    content3 = b"malicious code"
    print(f"Test 3 - Invalid extension: {handle_file_upload('script.exe', content3)}")
    
    # Test Case 4: Path traversal attempt
    content4 = b"test"
    print(f"Test 4 - Path traversal: {handle_file_upload('../../etc/passwd', content4)}")
    
    # Test Case 5: Large file (simulated)
    content5 = bytes(MAX_FILE_SIZE + 1)
    print(f"Test 5 - Oversized file: {handle_file_upload('large.txt', content5)}")

if __name__ == "__main__":
    main()
