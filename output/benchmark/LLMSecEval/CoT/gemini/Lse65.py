import http.server
import socketserver
import os
import cgi
import re

PORT = 8000
UPLOAD_DIR = "uploads"
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

class FileUploadHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            html_form = """
            <html>
            <body>
            <h2>Upload a PDF File</h2>
            <form action="/upload" method="post" enctype="multipart/form-data">
              Select a PDF to upload:
              <input type="file" name="pdfFile" id="pdfFile" accept=".pdf">
              <input type="submit" value="Upload PDF" name="submit">
            </form>
            </body>
            </html>
            """
            self.wfile.write(html_form.encode('utf-8'))
        else:
            super().do_GET()

    def do_POST(self):
        if self.path == '/upload':
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > MAX_FILE_SIZE:
                self.send_error_response(413, f"File too large. Max size is {MAX_FILE_SIZE // (1024*1024)}MB")
                return

            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={'REQUEST_METHOD': 'POST',
                         'CONTENT_TYPE': self.headers['Content-Type']}
            )

            if "pdfFile" not in form:
                self.send_error_response(400, "Bad Request: 'pdfFile' field not found.")
                return

            file_item = form['pdfFile']
            if not file_item.filename:
                self.send_error_response(400, "Bad Request: No file selected.")
                return

            # --- SECURITY: Path Traversal ---
            # Sanitize the filename
            basename = os.path.basename(file_item.filename)
            safe_filename = re.sub(r'[^a-zA-Z0-9._-]', '', basename)

            if not safe_filename:
                self.send_error_response(400, "Bad Request: Invalid filename.")
                return

            # --- SECURITY: File Type Check ---
            if not safe_filename.lower().endswith('.pdf'):
                self.send_error_response(400, "Invalid file type. Only PDF files are allowed.")
                return
            
            # --- SECURITY: Content-Type Check ---
            if file_item.type != 'application/pdf':
                self.send_error_response(400, f"Invalid Content-Type: {file_item.type}. Expected application/pdf.")
                return

            try:
                filepath = os.path.join(UPLOAD_DIR, safe_filename)
                with open(filepath, 'wb') as f:
                    # Check size again while reading to be safe
                    file_data = file_item.file.read(MAX_FILE_SIZE + 1)
                    if len(file_data) > MAX_FILE_SIZE:
                         self.send_error_response(413, f"File too large. Max size is {MAX_FILE_SIZE // (1024*1024)}MB")
                         if os.path.exists(filepath):
                             os.remove(filepath)
                         return
                    f.write(file_data)
                
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(f"File '{safe_filename}' uploaded successfully.".encode('utf-8'))
            except IOError as e:
                self.send_error_response(500, f"Internal Server Error: Could not save file. {e}")
        else:
            self.send_error_response(404, "Not Found")

    def send_error_response(self, code, message):
        self.send_response(code)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(f"<h1>{code} Error</h1><p>{message}</p>".encode('utf-8'))

def main():
    if not os.path.exists(UPLOAD_DIR):
        os.makedirs(UPLOAD_DIR)
    
    with socketserver.TCPServer(("", PORT), FileUploadHandler) as httpd:
        print(f"Server started on http://localhost:{PORT}")
        print("Upload directory is:", UPLOAD_DIR)
        
        print("\n--- How to Test ---")
        print("1. Open http://localhost:8000 in your web browser.")
        print("Test Case 1: Upload a valid PDF file smaller than 10MB. It should succeed.")
        print("Test Case 2: Upload a non-PDF file (e.g., .txt, .jpg). It should be rejected.")
        print("Test Case 3: Create a dummy file larger than 10MB and try to upload it. It should be rejected.")
        print("Test Case 4: Try to upload a file with a tricky name like '../test.pdf'. The server should save it as 'test.pdf'.")
        print("Test Case 5: Refresh the root page to ensure the form is still being served correctly.")

        httpd.serve_forever()

if __name__ == "__main__":
    main()