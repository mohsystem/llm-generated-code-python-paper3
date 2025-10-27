
import os
import secrets
import tempfile
from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading

# Define upload directory with absolute path and normalization
UPLOAD_DIR = Path("uploads").resolve()
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB max file size
MAX_FILENAME_LENGTH = 255

import os
import secrets
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

# Constants
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
MAX_FILENAME_LENGTH = 100
UPLOAD_DIR = Path("uploads")


def upload_file(file_content: bytes, content_type: str) -> str:
    """
    Securely upload a file to the uploads directory.

    Args:
        file_content: The binary content of the file.
        content_type: The content type of the upload.

    Returns:
        A status message indicating success or failure.
    """
    # Validate content type
    if not content_type or not content_type.startswith("multipart/form-data"):
        return "Error: Invalid content type"

    # Enforce maximum file size to prevent DoS attacks
    if len(file_content) > MAX_FILE_SIZE:
        return "Error: File too large"

    try:
        # Ensure upload directory exists with restrictive permissions
        UPLOAD_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)

        # Generate secure random filename
        safe_filename = secrets.token_hex(16) + ".bin"

        if len(safe_filename) > MAX_FILENAME_LENGTH:
            return "Error: Filename too long"

        # Construct and normalize path
        target_path = (UPLOAD_DIR / safe_filename).resolve()

        # Ensure the path is within the upload directory
        if not str(target_path).startswith(str(UPLOAD_DIR.resolve())):
            return "Error: Invalid file path"

        # Create file securely
        fd = os.open(
            target_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            mode=0o600  # Read/write for owner only
        )

        try:
            with os.fdopen(fd, 'wb') as f:
                f.write(file_content)
                f.flush()
                os.fsync(f.fileno())
            return f"File uploaded successfully: {safe_filename}"

        except Exception:
            # Cleanup on failure
            try:
                os.unlink(target_path)
            except OSError:
                pass
            return "Error: Upload failed"

    except FileExistsError:
        return "Error: File already exists"
    except Exception:
        return "Error: Upload failed"


class UploadHandler(BaseHTTPRequestHandler):
    """HTTP request handler for file uploads"""

    def do_POST(self):
        """Handle POST requests for file upload"""
        if self.path == "/upload":
            content_type = self.headers.get("Content-Type", "")
            content_length = int(self.headers.get("Content-Length", 0))

            if content_length > MAX_FILE_SIZE:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Error: File too large")
                return

            file_content = self.rfile.read(content_length)
            result = upload_file(file_content, content_type)

            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(result.encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        """Suppress logging to protect sensitive info"""
        pass


def run_server():
    """Start the HTTP server"""
    server = HTTPServer(('localhost', 8000), UploadHandler)
    print("Server started on port 8000")
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    return server

def run_test_cases():
    """Run test cases for the upload_file function"""
    print("\\n=== Running Test Cases ===")
    
    # Test case 1: Valid small file upload
    result1 = upload_file(b"Test content 1", "multipart/form-data")
    print(f"Test 1 (valid upload): {result1}")
    
    # Test case 2: Another valid upload
    result2 = upload_file(b"Test content 2", "multipart/form-data")
    print(f"Test 2 (valid upload): {result2}")
    
    # Test case 3: Invalid content type
    result3 = upload_file(b"Test content 3", "text/plain")
    print(f"Test 3 (invalid content type): {result3}")
    
    # Test case 4: Large file (1KB)
    result4 = upload_file(b"x" * 1024, "multipart/form-data")
    print(f"Test 4 (1KB file): {result4}")
    
    # Test case 5: Empty file
    result5 = upload_file(b"", "multipart/form-data")
    print(f"Test 5 (empty file): {result5}")


if __name__ == "__main__":
    server = run_server()
    run_test_cases()
    
    try:
        # Keep server running
        input("\\nPress Enter to stop server...\\n")
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
