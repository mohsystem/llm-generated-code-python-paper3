
import os
import secrets
import base64
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs
import cgi

UPLOAD_DIR = "uploads"
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
MAX_FILENAME_LENGTH = 255

def save_file(filename, content):
    """\n    Validate and save file securely\n    """
    # Input validation: check filename
    if not filename or len(filename) > MAX_FILENAME_LENGTH:
        raise ValueError("Invalid filename")
    
    # Sanitize filename: get basename only (removes path components)
    filename = os.path.basename(filename)
    # Remove potentially dangerous characters
    filename = "".join(c if c.isalnum() or c in "._-" else "_" for c in filename)
    
    # Validate PDF extension
    if not filename.lower().endswith(".pdf"):
        raise ValueError("Only PDF files allowed")
    
    # Check file size
    if not content or len(content) == 0 or len(content) > MAX_FILE_SIZE:
        raise ValueError("Invalid file size")
    
    # Validate PDF magic bytes (PDF header: %PDF-)
    if len(content) < 5 or content[:5] != b'%PDF-':
        raise ValueError("Not a valid PDF file")
    
    # Generate unique filename to prevent overwrites
    unique_id = base64.urlsafe_b64encode(secrets.token_bytes(16)).decode('ascii').rstrip('=')
    safe_name = f"{unique_id}_{filename}"
    
    # Resolve base directory
    base_dir = Path(UPLOAD_DIR).resolve()
    base_dir.mkdir(mode=0o700, exist_ok=True)
    
    target_path = (base_dir / safe_name).resolve()
    
    # Verify resolved path is within base directory (prevent path traversal)
    if not str(target_path).startswith(str(base_dir)):
        raise SecurityError("Path traversal attempt detected")
    
    # Use os.open with O_CREAT|O_EXCL for safe file creation
    # O_EXCL ensures we don't overwrite existing files\n    fd = None\n    try:\n        # Open with restrictive permissions (owner read/write only)\n        fd = os.open(target_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)\n        \n        # Write content\n        os.write(fd, content)\n        \n        # Ensure data is written to disk\n        os.fsync(fd)\n        \n        return f"File uploaded successfully: {safe_name}"\n        \n    finally:\n        if fd is not None:\n            os.close(fd)\n\nclass UploadHandler(BaseHTTPRequestHandler):\n    def do_GET(self):\n        """Serve upload form"""\n        html = b"""<!DOCTYPE html>\n<html>\n<head><title>PDF Upload</title></head>\n<body>\n<h1>Upload PDF File</h1>\n<form action='/upload' method='post' enctype='multipart/form-data'>\n<input type='file' name='file' accept='.pdf' required>\n<input type='submit' value='Upload'>\n</form>\n</body>\n</html>"""\n        self.send_response(200)\n        self.send_header("Content-Type", "text/html; charset=utf-8")\n        self.send_header("Content-Length", str(len(html)))\n        self.end_headers()\n        self.wfile.write(html)\n    \n    def do_POST(self):\n        """Handle file upload"""\n        if self.path != "/upload":\n            self.send_error(404)\n            return\n        \n        try:\n            # Parse multipart form data\n            content_type = self.headers.get('Content-Type')\n            if not content_type or not content_type.startswith('multipart/form-data'):\n                self.send_error(400, "Invalid content type")\n                return\n            \n            # Parse with size limit\n            form = cgi.FieldStorage(\n                fp=self.rfile,\n                headers=self.headers,\n                environ={\n                    'REQUEST_METHOD': 'POST',\n                    'CONTENT_TYPE': content_type,\n                }\n            )\n            \n            if 'file' not in form:\n                self.send_error(400, "No file uploaded")\n                return\n            \n            file_item = form['file']\n            \n            if not file_item.file:\n                self.send_error(400, "Invalid file data")\n                return\n            \n            # Read file content with size check\n            content = file_item.file.read(MAX_FILE_SIZE + 1)\n            if len(content) > MAX_FILE_SIZE:\n                self.send_error(400, "File too large")\n                return\n            \n            filename = file_item.filename\n            if not filename:\n                self.send_error(400, "No filename provided")\n                return\n            \n            # Save file securely\n            result = save_file(filename, content)\n            \n            response = result.encode('utf-8')\n            self.send_response(200)\n            self.send_header("Content-Type", "text/plain; charset=utf-8")\n            self.send_header("Content-Length", str(len(response)))\n            self.end_headers()\n            self.wfile.write(response)\n            \n        except Exception as e:\n            error_msg = "Upload failed"\n            self.send_error(500, error_msg)\n    \n    def log_message(self, format, *args):\n        """Override to prevent logging sensitive data"""\n        pass\n\ndef main():\n    """Start server with test cases"""\n    # Create uploads directory\n    Path(UPLOAD_DIR).mkdir(mode=0o700, exist_ok=True)\n    \n    server = HTTPServer(('localhost', 8000), UploadHandler)
    print("Server started on http://localhost:8000")
    print("\\nTest Cases:")
    print("1. Valid PDF upload")
    print("2. File too large")
    print("3. Invalid filename with path traversal")
    print("4. Non-PDF file")
    print("5. Empty file")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()

if __name__ == "__main__":
    main()
