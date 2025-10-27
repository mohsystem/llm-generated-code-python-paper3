
import os
import secrets
import base64
import mysql.connector
from pathlib import Path
from typing import Optional

# Constants for secure file handling
UPLOAD_BASE_DIR = "/var/app/uploads"
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
DB_CONFIG = {
    'host': 'localhost',
    'user': 'appuser',
    'password': os.environ.get('DB_PASSWORD', ''),  # Never hardcode passwords
    'database': 'filedb',
    'ssl_ca': '/path/to/ca.pem',  # Enable SSL for database
    'ssl_disabled': False
}

def upload_pdf(file_data: bytes, original_filename: str) -> str:
    """\n    Upload PDF file securely: validates input, saves with random name, stores in database.\n    Returns the stored filepath.\n    """
    # Input validation: check file data exists and is not empty
    if not file_data or len(file_data) == 0:
        raise ValueError("File data is empty")
    
    # Validate file size to prevent resource exhaustion
    if len(file_data) > MAX_FILE_SIZE:
        raise ValueError("File size exceeds maximum allowed")
    
    # Validate original filename
    if not original_filename or not isinstance(original_filename, str):
        raise ValueError("Invalid filename")
    
    # Sanitize filename: remove path separators and dangerous characters
    sanitized = "".join(c if c.isalnum() or c in "._-" else "_" for c in original_filename)
    if not sanitized:
        sanitized = "file.pdf"
    
    # Validate PDF magic bytes (PDF files start with %PDF-)
    if len(file_data) < 5 or file_data[:5] != b'%PDF-':
        raise ValueError("File is not a valid PDF")
    
    # Generate cryptographically secure random filename
    random_bytes = secrets.token_bytes(16)
    random_name = base64.urlsafe_b64encode(random_bytes).decode('ascii').rstrip('=') + ".pdf"
    
    # Ensure upload directory exists with restricted permissions
    base_path = Path(UPLOAD_BASE_DIR).resolve()
    base_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    
    # Construct target path and validate it stays within base directory
    target_path = (base_path / random_name).resolve()
    if not str(target_path).startswith(str(base_path) + os.sep):
        raise SecurityError("Path traversal attempt detected")
    
    # Write file securely: create temp file, write, then atomic rename
    # Use os.open with O_CREAT|O_EXCL to prevent race conditions
    temp_name = f"upload_{secrets.token_hex(8)}.tmp"
    temp_path = base_path / temp_name
    
    try:
        # Open with restricted permissions (0600 - owner read/write only)
        fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            # Write data
            os.write(fd, file_data)
            # Ensure data is flushed to disk
            os.fsync(fd)
        finally:
            os.close(fd)
        
        # Atomic rename to final location
        os.replace(temp_path, target_path)
        
    except Exception as e:
        # Clean up temp file on failure
        try:
            temp_path.unlink(missing_ok=True)
        except:
            pass
        raise e
    
    # Store filepath in database using parameterized query to prevent SQL injection
    relative_path = random_name
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(prepared=True)
        
        # Parameterized query prevents SQL injection
        query = "INSERT INTO uploaded_files (filepath, original_name, upload_time) VALUES (%s, %s, NOW())"
        cursor.execute(query, (relative_path, sanitized))
        
        conn.commit()
        cursor.close()
        conn.close()
        
    except mysql.connector.Error as e:
        # Clean up file if database insert fails
        try:
            target_path.unlink(missing_ok=True)
        except:
            pass
        raise e
    
    return relative_path


def download_pdf(filepath: str) -> bytes:
    """\n    Download PDF file securely: validates path, reads from secure location.\n    Returns the file data.\n    """
    # Input validation: reject null or empty filepath
    if not filepath or not isinstance(filepath, str):
        raise ValueError("Invalid filepath")
    
    # Sanitize filepath
    sanitized = "".join(c if c.isalnum() or c in "._-" else "" for c in filepath)
    if not sanitized or not sanitized.endswith(".pdf"):
        raise ValueError("Invalid filepath format")
    
    # Construct path and validate it stays within base directory
    base_path = Path(UPLOAD_BASE_DIR).resolve()
    target_path = (base_path / sanitized).resolve()
    # Critical: ensure resolved path is within base directory (prevent path traversal)
    if not str(target_path).startswith(str(base_path) + os.sep):
        raise SecurityError("Path traversal attempt detected")

    # Open file using os.open with O_NOFOLLOW to prevent symlink attacks
    # Validate it's a regular file and within size limits
    try:
        # Open file descriptor without following symlinks
        fd = os.open(target_path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            # Use fstat on the open file descriptor (race-safe)
            stat_info = os.fstat(fd)

            # Validate it's a regular file
            import stat as stat_module

            if not stat_module.S_ISREG(stat_info.st_mode):
                raise SecurityError("Not a regular file")

            # Validate size
            if stat_info.st_size > MAX_FILE_SIZE or stat_info.st_size < 5:
                raise ValueError("File size out of bounds")

            # Read file data from the open descriptor
            data = os.read(fd, stat_info.st_size)

        finally:
            os.close(fd)

    except FileNotFoundError:
        raise FileNotFoundError("File not found")
    except OSError as e:
        if e.errno == 40:  # ELOOP - too many symbolic links
            raise SecurityError("Symlink detected")
        raise

    # Validate PDF magic bytes before returning
    if len(data) < 5 or data[:5] != b"%PDF-":
        raise SecurityError("File corruption detected")

    return data



class SecurityError(Exception):
    """Custom exception for security violations"""
    pass


if __name__ == "__main__":
    # Test case 1: Valid PDF upload
    try:
        valid_pdf = b'%PDF-1.4\\n%test content'
        path1 = upload_pdf(valid_pdf, "document.pdf")
        print(f"Test 1 - Upload valid PDF: {path1}")
    except Exception as e:
        print(f"Test 1 - Error: {e}")
    
    # Test case 2: Download uploaded file
    try:
        downloaded = download_pdf(path1)
        print(f"Test 2 - Download PDF: {len(downloaded)} bytes")
    except Exception as e:
        print(f"Test 2 - Error: {e}")
    
    # Test case 3: Invalid PDF (missing magic bytes)
    try:
        upload_pdf(b'\\x00\\x00\\x00', "invalid.pdf")
        print("Test 3 - Should have rejected invalid PDF")
    except ValueError:
        print("Test 3 - Correctly rejected invalid PDF")
    
    # Test case 4: Path traversal attempt in upload
    try:
        upload_pdf(valid_pdf, "../../../etc/passwd.pdf")
        print("Test 4 - Should have blocked path traversal")
    except Exception:
        print("Test 4 - Correctly blocked path traversal")
    
    # Test case 5: Path traversal attempt in download
    try:
        download_pdf("../../../etc/passwd")
        print("Test 5 - Should have blocked path traversal")
    except Exception:
        print("Test 5 - Correctly blocked path traversal")
