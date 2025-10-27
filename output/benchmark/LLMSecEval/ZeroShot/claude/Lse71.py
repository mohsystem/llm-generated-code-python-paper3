
from http.server import HTTPServer, BaseHTTPRequestHandler
import cgi
import os
import uuid
import re
from urllib.parse import parse_qs

class Lse71(BaseHTTPRequestHandler):
    UPLOAD_DIR = "./uploads/"
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'jpg', 'jpeg', 'png', 'gif', 'doc', 'docx'}

    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            html = """\n            <html><body>\n            <h2>Secure File Upload</h2>\n            <form action='/upload' method='post' enctype='multipart/form-data'>\n            <input type='file' name='file' required>\n            <input type='submit' value='Upload'>\n            </form></body></html>\n            """
            self.wfile.write(html.encode())
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path == '/upload':
            try:
                content_type = self.headers['Content-Type']
                if not content_type or 'multipart/form-data' not in content_type:
                    self.send_error(400, "Invalid content type")
                    return

                form = cgi.FieldStorage(
                    fp=self.rfile,
                    headers=self.headers,
                    environ={'REQUEST_METHOD': 'POST'}
                )

                if 'file' not in form:
                    self.send_error(400, "No file uploaded")
                    return

                file_item = form['file']
                if not file_item.filename:
                    self.send_error(400, "Empty filename")
                    return

                # Validate file size
                file_data = file_item.file.read()
                if len(file_data) > self.MAX_FILE_SIZE:
                    self.send_error(413, "File too large")
                    return

                # Validate file extension
                filename = os.path.basename(file_item.filename)
                if not self.is_valid_file(filename):
                    self.send_error(400, "Invalid file type")
                    return

                # Sanitize and save file
                safe_name = self.sanitize_filename(filename)
                unique_name = f"{uuid.uuid4()}_{safe_name}"
                
                os.makedirs(self.UPLOAD_DIR, exist_ok=True)
                filepath = os.path.join(self.UPLOAD_DIR, unique_name)
                
                with open(filepath, 'wb') as f:
                    f.write(file_data)

                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(f"File uploaded successfully: {unique_name}".encode())

            except Exception as e:
                self.send_error(500, f"Upload failed: {str(e)}")
        else:
            self.send_error(404)

    def is_valid_file(self, filename):
        ext = self.get_file_extension(filename).lower()
        return ext in self.ALLOWED_EXTENSIONS

    def get_file_extension(self, filename):
        return os.path.splitext(filename)[1][1:] if '.' in filename else ''

    def sanitize_filename(self, filename):
        return re.sub(r'[^a-zA-Z0-9._-]', '_', filename)

def main():
    os.makedirs("./uploads/", exist_ok=True)
    server = HTTPServer(('localhost', 8080), Lse71)
    print("Server started on port 8080")
    print("Test cases: Open browser and navigate to http://localhost:8080")
    print("1. Upload a valid .txt file")
    print("2. Upload a valid .jpg file")
    print("3. Try uploading an invalid file type (.exe)")
    print("4. Try uploading a file larger than 10MB")
    print("5. Try uploading with special characters in filename")
    server.serve_forever()

if __name__ == "__main__":
    main()
