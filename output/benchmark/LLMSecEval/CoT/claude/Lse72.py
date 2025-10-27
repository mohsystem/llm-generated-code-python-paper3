
import os
import re
from pathlib import Path

class Lse72:
    UPLOAD_DIR = "uploads"
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
    ALLOWED_EXTENSIONS = {'.txt', '.pdf', '.jpg', '.png', '.doc', '.docx'}
    
    @staticmethod
    def upload_file(file_content, filename):
        try:
            # Validate filename
            if not filename or not filename.strip():
                return "Error: Invalid filename"
            
            # Sanitize filename
            sanitized_filename = Lse72.sanitize_filename(filename)
            if not sanitized_filename:
                return "Error: Invalid filename after sanitization"
            
            # Validate file extension
            if not Lse72.is_allowed_extension(sanitized_filename):
                return "Error: File type not allowed"
            
            # Validate file size
            if len(file_content) > Lse72.MAX_FILE_SIZE:
                return "Error: File size exceeds limit"
            
            # Create uploads directory if it doesn't exist\n
            upload_path = Path(Lse72.UPLOAD_DIR).resolve()
            upload_path.mkdir(parents=True, exist_ok=True)
            # Create secure file path\n
            file_path = (upload_path / sanitized_filename).resolve()
            # Verify the resolved path is still within uploads directory\n
            if not str(file_path).startswith(str(upload_path)):
                return "Error: Invalid file path"
            # Save file\n
            with open(file_path, 'wb') as f:
                f.write(file_content)
                return f"Success: File uploaded to {file_path}"
        except Exception as e:
                return f"Error: {str(e)}"
@staticmethod
def sanitize_filename(filename):
# Get base filename without path\n
        name = os.path.basename(filename)
        # Remove any character that isn't alphanumeric, dot, dash, or underscore
        name = re.sub(r'[^a-zA-Z0-9._-]', '_', name)
        
        # Remove leading dots to prevent hidden files
        name = re.sub(r'^\\.+', '', name)
        
        # Limit filename length
        if len(name) > 255:
            name = name[:255]
        
        return name
    
@staticmethod
def is_allowed_extension(filename):
    return any(filename.lower().endswith(ext) for ext in Lse72.ALLOWED_EXTENSIONS)


if __name__ == "__main__":
    # Test case 1: Valid file
    content1 = b"Test content"
    print("Test 1:", Lse72.upload_file(content1, "document.txt"))
    
    # Test case 2: Path traversal attempt
    content2 = b"Malicious content"
    print("Test 2:", Lse72.upload_file(content2, "../../../etc/passwd"))
    
    # Test case 3: Invalid extension
    content3 = b"Script content"
    print("Test 3:", Lse72.upload_file(content3, "malicious.exe"))
    
    # Test case 4: Valid image file
    content4 = b"x" * 1024
    print("Test 4:", Lse72.upload_file(content4, "photo.jpg"))
    
    # Test case 5: Empty filename
    content5 = b"Content"
    print("Test 5:", Lse72.upload_file(content5, ""))
