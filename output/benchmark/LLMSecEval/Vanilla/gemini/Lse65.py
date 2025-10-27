import os
import threading
import time
import cgi
from http.server import BaseHTTPRequestHandler, HTTPServer
import requests # Note: This is a third-party library. Install with: pip install requests
import pathlib

UPLOAD_DIR = "uploads"
PORT = 8081
SERVER_URL = f"http://localhost:{PORT}"

# --- Server-side Code ---
class FileUploadHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/upload':
            try:
                # Create uploads directory if it doesn't exist
                os.makedirs(UPLOAD_DIR, exist_ok=True)
                
                ctype, pdict = cgi.parse_header(self.headers.get('content-type'))
                if ctype == 'multipart/form-data':
                    pdict['boundary'] = bytes(pdict['boundary'], "utf-8")
                    fields = cgi.parse_multipart(self.rfile, pdict)
                    
                    # 'file' is the name of the form field
                    file_data = fields.get('file')[0]
                    
                    # Extract filename from Content-Disposition header
                    # A more robust way is needed for complex cases, but this works for simple ones
                    form = cgi.FieldStorage(
                        fp=self.rfile,
                        headers=self.headers,
                        environ={'REQUEST_METHOD': 'POST',
                                 'CONTENT_TYPE': self.headers['Content-Type'],
                                 })
                    filename = form['file'].filename
                    
                    filepath = os.path.join(UPLOAD_DIR, filename)
                    with open(filepath, 'wb') as f:
                        f.write(file_data)
                    
                    response_message = f"File '{filename}' uploaded successfully."
                    print(f"Server: {response_message}")
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(response_message.encode('utf-8'))
                else:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"Bad Request: Content-Type must be multipart/form-data.")
            except Exception as e:
                print(f"Server Error: {e}")
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f"Internal Server Error: {e}".encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

def run_server(server_class=HTTPServer, handler_class=FileUploadHandler, port=PORT):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f"Server started on port {port}")
    httpd.serve_forever()
    return httpd
    
# --- Client-side Code ---
def upload_pdf_file(file_path):
    """
    Uploads a file to the local web server.
    """
    try:
        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f, 'application/pdf')}
            response = requests.post(f"{SERVER_URL}/upload", files=files)
            return f"Status: {response.status_code}, Response: {response.text}"
    except requests.exceptions.RequestException as e:
        return f"Client Error: {e}"

# --- Main function with test cases ---
def main():
    # 1. Start Server in a separate thread
    server = HTTPServer(('', PORT), FileUploadHandler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    print(f"Server thread started. Waiting a moment for it to initialize...")
    time.sleep(1)

    test_files = []
    try:
        # 2. Setup test directory and files
        os.makedirs(UPLOAD_DIR, exist_ok=True)

        print("\n--- Running 5 Test Cases ---")
        for i in range(1, 6):
            file_name = f"test_file_{i}.pdf"
            test_files.append(file_name)
            with open(file_name, "w") as f:
                f.write(f"This is a dummy PDF file content for test {i}")

            print(f"\nTest Case {i}: Uploading {file_name}")
            result = upload_pdf_file(file_name)
            print(f"Client Result: {result}")
            
            # Verify file exists in uploads directory
            if os.path.exists(os.path.join(UPLOAD_DIR, file_name)):
                print(f"Verification: SUCCESS - File found in '{UPLOAD_DIR}' folder.")
            else:
                print(f"Verification: FAILED - File not found in '{UPLOAD_DIR}' folder.")

    finally:
        # 4. Stop Server
        print("\nShutting down server...")
        server.shutdown()
        server.server_close()
        server_thread.join()
        print("Server stopped.")

        # 5. Cleanup
        print("Cleaning up test files...")
        for f in test_files:
            if os.path.exists(f):
                os.remove(f)
        # Note: The uploads directory is not deleted to allow inspection of results.

if __name__ == "__main__":
    main()