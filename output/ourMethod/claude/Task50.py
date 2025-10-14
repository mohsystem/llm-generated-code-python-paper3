
import os
import secrets
import re
from pathlib import Path
from typing import Optional

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
MAX_FILENAME_LENGTH = 255
SAFE_FILENAME_PATTERN = re.compile(r'^[a-zA-Z0-9_\\-\\.]+$')
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'jpg', 'jpeg', 'png', 'gif', 'doc', 'docx', 'csv'}


class FileUploader:
    def __init__(self, base_dir: str) -> None:
        if not base_dir or not base_dir.strip():
            raise ValueError("Base directory cannot be null or empty")
        
        self.upload_directory = Path(base_dir).resolve()
        
        if not self.upload_directory.exists():
            self.upload_directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        
        if not self.upload_directory.is_dir():
            raise ValueError("Upload path must be a directory")
    
    def _sanitize_filename(self, filename: str) -> str:
        if not filename or not filename.strip():
            raise ValueError("Filename cannot be null or empty")
        
        filename = filename.strip()
        
        if len(filename) > MAX_FILENAME_LENGTH:
            raise ValueError("Filename too long")
        
        if not SAFE_FILENAME_PATTERN.match(filename):
            raise ValueError("Filename contains invalid characters")
        
        extension = self._get_file_extension(filename)
        if extension.lower() not in ALLOWED_EXTENSIONS:
            raise ValueError("File type not allowed")
        
        return filename
    
    def _get_file_extension(self, filename: str) -> str:
        if '.' in filename:
            return filename.rsplit('.', 1)[1]
        return ""
    
    def _validate_upload_path(self, filename: str) -> Path:
        sanitized = self._sanitize_filename(filename)
        target_path = (self.upload_directory / sanitized).resolve()
        
        if not str(target_path).startswith(str(self.upload_directory)):
            raise SecurityError("Path traversal attempt detected")
        
        if target_path.is_symlink():
            raise SecurityError("Symbolic links are not allowed")
        
        return target_path
    
    def _generate_unique_filename(self, original_filename: str) -> str:
        random_hex = secrets.token_hex(8)
        extension = self._get_file_extension(original_filename)
        base_name = original_filename.rsplit('.', 1)[0]
        return f"{base_name}_{random_hex}.{extension}"
    
    def upload_file(self, filename: str, content: bytes) -> str:
        if content is None:
            return "ERROR: File content cannot be null"
        
        if len(content) == 0:
            return "ERROR: File content cannot be empty"
        
        if len(content) > MAX_FILE_SIZE:
            return "ERROR: File size exceeds maximum allowed size"
        
        try:
            target_path = self._validate_upload_path(filename)
            
            unique_filename = self._generate_unique_filename(filename)
            unique_path = (self.upload_directory / unique_filename).resolve()
            
            if not str(unique_path).startswith(str(self.upload_directory)):
                return "ERROR: Invalid file path"
            
            temp_fd, temp_path = None, None
            try:
                import tempfile
                temp_fd, temp_path_str = tempfile.mkstemp(dir=self.upload_directory, prefix="upload_", suffix=".tmp")
                temp_path = Path(temp_path_str)
                
                os.write(temp_fd, content)
                os.close(temp_fd)
                temp_fd = None
                
                temp_path.replace(unique_path)
                
                os.chmod(unique_path, 0o600)
                
                return f"SUCCESS: File uploaded as {unique_filename}"
                
            except Exception as e:
                if temp_fd is not None:
                    try:
                        os.close(temp_fd)
                    except:
                        pass
                if temp_path and temp_path.exists():
                    try:
                        temp_path.unlink()
                    except:
                        pass
                raise
            
        except (ValueError, SecurityError) as e:
            return f"ERROR: {str(e)}"
        except Exception:
            return "ERROR: Failed to upload file"


class SecurityError(Exception):
    pass


def main() -> None:
    import tempfile
    
    test_dir = os.path.join(tempfile.gettempdir(), "test_uploads")
    uploader = FileUploader(test_dir)
    
    # Test case 1: Valid text file
    result1 = uploader.upload_file("test1.txt", b"Hello World")
    print(f"Test 1: {result1}")
    
    # Test case 2: Valid PDF file
    pdf_content = secrets.token_bytes(1024)
    result2 = uploader.upload_file("document.pdf", pdf_content)
    print(f"Test 2: {result2}")
    
    # Test case 3: Invalid filename (path traversal attempt)
    result3 = uploader.upload_file("../etc/passwd.txt", b"malicious")
    print(f"Test 3: {result3}")
    
    # Test case 4: File too large
    large_content = bytes(MAX_FILE_SIZE + 1)
    result4 = uploader.upload_file("large.txt", large_content)
    print(f"Test 4: {result4}")
    
    # Test case 5: Invalid file extension
    result5 = uploader.upload_file("malware.exe", b"test")
    print(f"Test 5: {result5}")


if __name__ == "__main__":
    main()
