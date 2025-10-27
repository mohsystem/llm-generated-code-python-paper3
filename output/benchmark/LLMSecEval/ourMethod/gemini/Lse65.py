import http.server
import socketserver
import os
import cgi
import re
import uuid
from pathlib import Path
import threading
import time
import requests # Note: This script requires the 'requests' library: pip install requests

# --- Server Configuration ---
HOST = "localhost"
PORT = 8080
UPLOAD_DIR = Path("uploads")
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

class FileUploadHandler(http.server.BaseHTTPRequestHandler):
    
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            html_form = """
            <!DOCTYPE html>
            <html>
            <head><title>File Upload</title></head>
            <body>
                <h2>Upload PDF File</h2>
                <form action="/upload" method="post" enctype="multipart/form-data">
                    Select PDF file to upload:
                    <input type="file" name="fileToUpload" id="fileToUpload" accept=".pdf" required>
                    <input type="submit" value="Upload PDF" name="submit">
                </form>
            </body>
            </html>
            """
            self.wfile.write(html_form.encode('utf-8'))
        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        if self.path == '/upload':
            try:
                content_type, pdict = cgi.parse_header(self.headers.get('content-type'))
                
                if content_type != 'multipart/form-data':
                    self.send_error(400, "Bad Request: Expected multipart/form-data")
                    return
                
                # cgi.FieldStorage is a safe way to parse form data, handling size limits.
                # It reads from self.rfile, which is a buffered stream.
                pdict['boundary'] = bytes(pdict['boundary'], "utf-8")
                
                content_length = int(self.headers['Content-Length'])
                if content_length > MAX_FILE_SIZE:
                    self.send_error(413, f"Payload Too Large: File size exceeds {MAX_FILE_SIZE} bytes.")
                    return

                fields = cgi.parse_multipart(self.rfile, pdict)
                
                if 'fileToUpload' not in fields:
                    self.send_error(400, "Bad Request: 'fileToUpload' field is missing.")
                    return

                file_item_list = fields['fileToUpload']
                if not file_item_list:
                    self.send_error(400, "Bad Request: No file selected.")
                    return

                file_content = file_item_list[0]

                # --- Security: Sanitize filename ---
                # From headers, not from the potentially malicious `filename` attribute
                # in cgi.FieldStorage as it's parsed from the request body.
                # A robust way is to parse the part header manually if needed, but for now we extract from cgi.
                # Let's get the filename from the Content-Disposition header.
                disp_header = self.headers.get('Content-Disposition')
                
                # A simple regex to find the filename in the first part
                # In a real app, a proper multipart parser would be used.
                # cgi.FieldStorage is tricky as it doesn't expose the original filename easily.
                # A simple but effective way: just check the content-disposition of the part header.
                # Since cgi.parse_multipart doesn't give us headers, we have to trust the field name.
                # The filename can be retrieved from header directly.
                # A better approach: re-parsing with more control.
                # However, for this example, we proceed with a pragmatic check.
                # We need to find the filename from the first part's header.
                # Since cgi.parse_multipart consumes the stream, we'd need to pre-read.
                # For simplicity, we'll assume the field name 'fileToUpload' is constant.
                
                # We get the filename from the parsed form data.
                # The `filename` attribute on the FieldStorage item is what we need.
                # It is up to us to sanitize it.
                # A proper way to re-get it:
                form = cgi.FieldStorage(
                    fp=self.rfile,
                    headers=self.headers,
                    environ={'REQUEST_METHOD': 'POST',
                             'CONTENT_TYPE': self.headers['Content-Type'],
                             })
                
                if 'fileToUpload' not in form or not form['fileToUpload'].filename:
                    self.send_error(400, "Bad Request: No file in 'fileToUpload' field.")
                    return

                file_item = form['fileToUpload']
                original_filename = file_item.filename

                sanitized_basename = Path(original_filename).name
                if not sanitized_basename or not sanitized_basename.lower().endswith('.pdf'):
                    self.send_error(400, "Bad Request: Invalid file. Only PDF files are allowed.")
                    return
                
                # Generate a unique filename
                unique_filename = f"{uuid.uuid4()}_{sanitized_basename}"

                # --- Security: Path Traversal Check ---
                base_path = UPLOAD_DIR.resolve()
                destination_path = (base_path / unique_filename).resolve()

                if base_path not in destination_path.parents:
                    self.send_error(400, "Bad Request: Invalid file path (Path Traversal attempt).")
                    return
                
                # The file data is in file_item.file
                with open(destination_path, 'wb') as f:
                    # file_item.file is a file-like object, read from it
                    file_data = file_item.file.read()
                    
                    if len(file_data) > MAX_FILE_SIZE:
                         self.send_error(413, f"Payload Too Large: File size exceeds {MAX_FILE_SIZE} bytes.")
                         if os.path.exists(destination_path):
                             os.remove(destination_path)
                         return

                    f.write(file_data)
                
                print(f"File saved: {destination_path}")
                self.send_response(200)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(b"File uploaded successfully!")

            except Exception as e:
                print(f"Error handling upload: {e}")
                self.send_error(500, f"Internal Server Error: {e}")
        else:
            self.send_error(404, "Not Found")

def run_server():
    UPLOAD_DIR.mkdir(exist_ok=True)
    print(f"Upload directory '{UPLOAD_DIR.resolve()}' is ready.")
    
    with socketserver.TCPServer((HOST, PORT), FileUploadHandler) as httpd:
        print(f"Server started on http://{HOST}:{PORT}")
        print("Visit http://localhost:8080 to upload a file.")
        httpd.serve_forever()

def run_test_cases():
    print("\n--- Running 5 Test Cases ---")
    base_url = f"http://{HOST}:{PORT}/upload"

    def test_upload(filename, content, content_type, expect_success):
        try:
            with open(filename, "w") as f:
                f.write(content)
            
            with open(filename, "rb") as f:
                files = {'fileToUpload': (filename, f, content_type)}
                try:
                    response = requests.post(base_url, files=files, timeout=15)
                    print(f"Test Case [{filename}]: ", end="")
                    if expect_success and response.status_code == 200:
                        print(f"PASSED (Status {response.status_code})")
                    elif not expect_success and response.status_code != 200:
                        print(f"PASSED (Status {response.status_code} as expected)")
                    else:
                        print(f"FAILED (Expected success={expect_success}, got status {response.status_code})")
                        print(f"   Response: {response.text}")
                except requests.exceptions.RequestException as e:
                    # For large file test, server might close connection.
                    if not expect_success and 'Connection aborted' in str(e):
                         print(f"Test Case [{filename}]: PASSED (Connection aborted as expected for large file)")
                    else:
                         print(f"Test Case [{filename}]: FAILED with request exception: {e}")

            os.remove(filename)
        except Exception as e:
            print(f"Test Case [{filename}]: FAILED with setup exception: {e}")

    # Test Case 1: Valid PDF upload
    test_upload("test1.pdf", "%PDF-1.4...", "application/pdf", True)
    # Test Case 2: Another valid PDF upload
    test_upload("document_final.pdf", "Fake PDF content", "application/pdf", True)
    # Test Case 3: Invalid file type
    test_upload("test3.txt", "This is a text file.", "text/plain", False)
    # Test Case 4: Path traversal attempt in filename
    test_upload("../../test4.pdf", "Attempting traversal.", "application/pdf", True) # Server sanitizes basename, so it should succeed safely
    # Test Case 5: File too large
    large_content = "a" * (MAX_FILE_SIZE + 1)
    test_upload("large_file.pdf", large_content, "application/pdf", False)
    
    print("--- Test Cases Finished ---\n")

if __name__ == "__main__":
    # Run server in a separate thread so we can run tests
    server_thread = threading.Thread(target=run_server)
    server_thread.daemon = True
    server_thread.start()
    
    # Give the server a moment to start up
    time.sleep(1)

    run_test_cases()
    
    print("Server is still running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down server.")