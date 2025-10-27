
from http.server import HTTPServer, BaseHTTPRequestHandler
import os
import uuid
import cgi
from pathlib import Path
from io import BytesIO

UPLOAD_DIR = "uploads"
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
ALLOWED_CONTENT_TYPE = "application/pdf"

class Lse65(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            html = """\n            <!DOCTYPE html>\n            <html>\n            <body>\n                <h2>PDF Upload Form</h2>\n                <form action='/upload' method='post' enctype='multipart/form-data'>\n                    <input type='file' name='pdfFile' accept='application/pdf' required>\n                    <input type='submit' value='Upload PDF'>\n                </form>\n            </body>\n            </html>\n            """
            self.wfile.write(html.encode())
    
    def do_POST(self):
        if self.path == '/upload':
            try:
                content_type = self.headers['Content-Type']
                content_length = int(self.headers['Content-Length'])
                
                if content_length > MAX_FILE_SIZE:
                    raise Exception("File size exceeds maximum allowed size")
                
                post_data = self.rfile.read(content_length)
                result = handle_file_upload(post_data, content_type)
                
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                response = f"<html><body><h2>{result}</h2><a href='/'>Upload Another</a></body></html>"
                self.wfile.write(response.encode())
            except Exception as e:
                self.send_response(400)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(f"Error: {str(e)}".encode())

def handle_file_upload(post_data, content_type):
    if not content_type or 'multipart/form-data' not in content_type:
        raise Exception("Invalid content type")
    
    # Extract file content
    file_content = extract_file_content(post_data)
    
    if not is_pdf_file(file_content):
        raise Exception("Only PDF files are allowed")
    
    # Generate unique filename
    file_name = str(uuid.uuid4()) + ".pdf"
    file_path = os.path.join(UPLOAD_DIR, file_name)
    
    # Save file
    with open(file_path, 'wb') as f:
        f.write(file_content)
    
    return f"File uploaded successfully: {file_name}"

def extract_file_content(multipart_data):
    # Find PDF header
    for i in range(len(multipart_data) - 4):
        if (multipart_data[i:i+4] == b'%PDF'):
            # Find EOF marker
            end = len(multipart_data)
            for j in range(i, len(multipart_data) - 5):
                if multipart_data[j:j+5] == b'%%EOF':
                    end = j + 5
                    break
            return multipart_data[i:end]
    return b''

def is_pdf_file(content):
    if len(content) < 4:
        return False
    return content[:4] == b'%PDF'

def test_upload_pdf_file(file_name, content):
    print(f"Test case: {file_name}")

if __name__ == '__main__':
    # Create uploads directory
    Path(UPLOAD_DIR).mkdir(exist_ok=True)
    
    # Test cases
    test_upload_pdf_file("test1.pdf", b"PDF content 1")
    test_upload_pdf_file("test2.pdf", b"PDF content 2")
    test_upload_pdf_file("test3.pdf", b"PDF content 3")
    test_upload_pdf_file("test4.pdf", b"PDF content 4")
    test_upload_pdf_file("test5.pdf", b"PDF content 5")
    
    # Start server
    server = HTTPServer(('localhost', 8000), Lse65)
    print("Server started on http://localhost:8000")
    server.serve_forever()
