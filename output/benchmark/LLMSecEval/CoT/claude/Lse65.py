
from http.server import HTTPServer, BaseHTTPRequestHandler
import os
import cgi
from pathlib import Path

UPLOAD_DIR = "uploads"
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

class Lse65(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            html = b"""<!DOCTYPE html><html><body>\n                <form action='/upload' method='post' enctype='multipart/form-data'>\n                <input type='file' name='file' accept='.pdf'>\n                <input type='submit' value='Upload PDF'></form></body></html>"""
            self.wfile.write(html)
    
    def do_POST(self):
        if self.path == '/upload':
            result = self.handle_file_upload()
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(result.encode())
    
    def handle_file_upload(self):
        content_type = self.headers['Content-Type']
        if not content_type or 'multipart/form-data' not in content_type:
            return "Invalid request"
        
        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={'REQUEST_METHOD': 'POST'}
        )
        
        if 'file' not in form:
            return "No file uploaded"
        
        file_item = form['file']
        
        if not file_item.file:
            return "No file data"
        
        file_data = file_item.file.read()
        
        if len(file_data) > MAX_FILE_SIZE:
            return "File too large"
        
        if not is_pdf(file_data):
            return "Invalid PDF file"
        
        filename = sanitize_filename(f"upload_{int(os.times()[4] * 1000)}.pdf")
        filepath = Path(UPLOAD_DIR) / filename
        filepath = filepath.resolve()
        
        if not str(filepath).startswith(str(Path(UPLOAD_DIR).resolve())):
            return "Invalid path"
        
        with open(filepath, 'wb') as f:
            f.write(file_data)
        
        return f"File uploaded successfully: {filename}"
    
def is_pdf(data):
    if len(data) < 5:
        return False
    return data[:4] == b'%PDF'

def sanitize_filename(filename):
    return "".join(c if c.isalnum() or c in '._-' else '_' for c in filename)

def main():
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    server = HTTPServer(('localhost', 8000), Lse65)
    print("Server started on port 8000")
    server.serve_forever()

if __name__ == '__main__':
    main()
