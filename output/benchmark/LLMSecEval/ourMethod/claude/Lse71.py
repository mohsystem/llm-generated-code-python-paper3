
import os
import secrets
import hashlib
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Optional

# Security: Define maximum file size to prevent DoS (10MB)
MAX_FILE_SIZE = 10 * 1024 * 1024
# Security: Define allowed file extensions whitelist
ALLOWED_EXTENSIONS = {'.txt', '.pdf', '.jpg', '.png'}
# Security: Define upload directory - must be outside web root
UPLOAD_DIR = 'uploads'
# Security: Maximum filename length to prevent buffer issues
MAX_FILENAME_LENGTH = 255


class SecureUploadHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        """Handle POST requests for file upload"""
        try:
            # Security: Only process requests to /upload endpoint
            if self.path != '/upload':
                self.send_error(404, "Not found")
                return

            # Security: Validate Content-Type header
            content_type = self.headers.get('Content-Type', '')
            if not content_type.startswith('multipart/form-data'):
                self.send_error(400, "Invalid content type")
                return

            # Security: Extract boundary
            boundary = self._extract_boundary(content_type)
            if not boundary:
                self.send_error(400, "Invalid boundary")
                return

            # Security: Read content with size limit
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > MAX_FILE_SIZE:
                self.send_error(400, "File too large")
                return

            # Security: Process upload with validation
            result = self._process_upload(boundary, content_length)
            
            if result.startswith("Error"):
                self.send_response(400)
            else:
                self.send_response(200)
            
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.end_headers()
            self.wfile.write(result.encode('utf-8'))

        except Exception as e:
            # Security: Return generic error message, log details separately
            print(f"Upload error: {e}")
            self.send_error(500, "Upload failed")

    def _extract_boundary(self, content_type: str) -> Optional[str]:
        """Security: Extract and validate boundary from Content-Type"""
        parts = content_type.split(';')
        for part in parts:
            part = part.strip()
            if part.startswith('boundary='):
                return '--' + part[9:]
        return None

    def _process_upload(self, boundary: str, content_length: int) -> str:
        """Process multipart upload with security validations"""
        try:
            # Security: Read with size limit
            remaining_bytes = content_length
            boundary_bytes = boundary.encode('utf-8')
            
            filename = None
            file_content = bytearray()
            in_file_content = False
            total_bytes_read = 0

            while remaining_bytes > 0:
                # Security: Read line by line with size check
                line = self.rfile.readline()
                if not line:
                    break
                
                total_bytes_read += len(line)
                remaining_bytes -= len(line)

                # Security: Enforce total size limit
                if total_bytes_read > MAX_FILE_SIZE:
                    return "Error: File size exceeds maximum limit"

                if line.startswith(boundary_bytes):
                    if in_file_content and filename:
                        # Save the file
                        result = self._save_file(filename, bytes(file_content))
                        if result:
                            return result
                    in_file_content = False
                    file_content = bytearray()
                    continue

                line_str = line.decode('utf-8', errors='ignore').strip()

                if 'content-disposition' in line_str.lower():
                    filename = self._extract_filename(line_str)
                    if not filename:
                        return "Error: Invalid filename"
                    continue

                if 'content-type' in line_str.lower():
                    self.rfile.readline()  # Skip blank line
                    remaining_bytes -= 2
                    in_file_content = True
                    continue

                if in_file_content:
                    file_content.extend(line)

            return "File uploaded successfully"

        except Exception as e:
            print(f"Processing error: {e}")
            return "Error: Upload failed"

    def _extract_filename(self, header: str) -> Optional[str]:
        """Security: Extract and validate filename from Content-Disposition header"""
        match = re.search(r'filename="([^"]+)"', header)
        if not match:
            return None

        filename = match.group(1)

        # Security: Validate filename length
        if len(filename) > MAX_FILENAME_LENGTH:
            return None

        # Security: Remove path traversal attempts - use only basename
        filename = os.path.basename(filename)

        # Security: Validate filename contains only safe characters
        if not re.match(r'^[a-zA-Z0-9_.-]+$', filename):
            return None

        # Security: Check file extension against whitelist
        _, extension = os.path.splitext(filename)
        extension = extension.lower()

        if extension not in ALLOWED_EXTENSIONS:
            return None

        return filename

    def _save_file(self, filename: str, content: bytes) -> Optional[str]:
        """Security: Save file with validation and safe operations"""
        try:
            # Security: Validate content size
            if len(content) > MAX_FILE_SIZE:
                return "Error: File too large"

            # Security: Generate random unique filename to prevent overwrites
            random_bytes = secrets.token_bytes(16)
            hash_obj = hashlib.sha256(random_bytes)
            unique_prefix = hash_obj.hexdigest()[:16]
            safe_filename = f"{unique_prefix}_{filename}"

            # Security: Construct path safely within upload directory
            upload_dir = Path(UPLOAD_DIR).resolve()
            target_path = (upload_dir / safe_filename).resolve()

            # Security: Verify resolved path is still within upload directory
            if not str(target_path).startswith(str(upload_dir)):
                return "Error: Invalid file path"

            # Security: Create temp file first for atomic write
            temp_path = upload_dir / f"upload_{secrets.token_hex(8)}.tmp"

            try:
                # Security: Write to temp file
                with open(temp_path, 'wb') as f:
                    f.write(content)
                    f.flush()
                    os.fsync(f.fileno())

                # Security: Set restrictive permissions (owner read/write only)
                os.chmod(temp_path, 0o600)

                # Security: Atomic move to final location
                temp_path.replace(target_path)

            except Exception as e:
                # Security: Clean up temp file on failure
                try:
                    temp_path.unlink(missing_ok=True)
                except Exception:
                    pass
                return "Error: Failed to save file"

            return None  # Success

        except Exception as e:
            print(f"Save error: {e}")
            return "Error: File save failed"


def is_valid_filename(filename: str) -> bool:
    """Test helper function to validate filename"""
    if not filename or len(filename) > MAX_FILENAME_LENGTH:
        return False

    filename = os.path.basename(filename)

    if not re.match(r'^[a-zA-Z0-9_.-]+$', filename):
        return False

    _, extension = os.path.splitext(filename)
    extension = extension.lower()

    return extension in ALLOWED_EXTENSIONS


def run_tests():
    """Run test cases for filename validation"""
    print("\\n=== Running Test Cases ===")

    # Test 1: Valid filename
    print("Test 1: Valid filename 'test.txt' - Expected: Pass")
    print(f"Result: {'PASS' if is_valid_filename('test.txt') else 'FAIL'}")

    # Test 2: Path traversal attempt
    print("\\nTest 2: Path traversal '../etc/passwd' - Expected: Fail")
    print(f"Result: {'PASS' if not is_valid_filename('../etc/passwd') else 'FAIL'}")

    # Test 3: Invalid extension
    print("\\nTest 3: Invalid extension 'file.exe' - Expected: Fail")
    print(f"Result: {'PASS' if not is_valid_filename('file.exe') else 'FAIL'}")

    # Test 4: Special characters
    print("\\nTest 4: Special characters 'file<>.txt' - Expected: Fail")
    print(f"Result: {'PASS' if not is_valid_filename('file<>.txt') else 'FAIL'}")

    # Test 5: Maximum length
    print("\\nTest 5: Filename exceeds max length - Expected: Fail")
    long_name = 'a' * 256 + '.txt'
    print(f"Result: {'PASS' if not is_valid_filename(long_name) else 'FAIL'}")


def main():
    """Main function to start server"""
    # Security: Create upload directory with restricted permissions
    upload_path = Path(UPLOAD_DIR)
    if not upload_path.exists():
        upload_path.mkdir(mode=0o700, parents=True)
    
    # Security: Ensure restrictive permissions
    os.chmod(upload_path, 0o700)

    server = HTTPServer(('localhost', 8080), SecureUploadHandler)
    print("Server started on port 8080")
    
    # Run test cases
    run_tests()
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\\nShutting down server")
        server.shutdown()


if __name__ == '__main__':
    main()
