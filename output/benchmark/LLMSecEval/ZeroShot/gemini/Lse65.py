import os
import requests
import threading
import time
import cgi
import shutil
from http.server import HTTPServer, BaseHTTPRequestHandler

# Note: You may need to install the 'requests' library:
# pip install requests

def upload_pdf_file(server_url, pdf_file_path):
    """
    Uploads a PDF file to a given URL.

    Args:
        server_url (str): The URL of the upload endpoint.
        pdf_file_path (str): The path to the PDF file.

    Returns:
        requests.Response or None: The response object from the server,
                                     or None if an error occurred.
    """
    if not os.path.exists(pdf_file_path) or not os.path.isfile(pdf_file_path):
        print(f"Error: File not found at '{pdf_file_path}'")
        return None

    try:
        with open(pdf_file_path, 'rb') as f:
            files = {'file': (os.path.basename(pdf_file_path), f, 'application/pdf')}
            response = requests.post(server_url, files=files, timeout=10)
            response.raise_for_status()  # Raise an exception for bad status codes
            return response
    except requests.exceptions.RequestException as e:
        print(f"An error occurred during upload: {e}")
        return None

# --- Test Server and Main Method for Demonstration ---

class UploadHandler(BaseHTTPRequestHandler):
    """A simple handler for POST requests to receive file uploads."""

    def do_POST(self):
        if self.path == '/upload':
            upload_dir = 'uploads'
            if not os.path.exists(upload_dir):
                os.makedirs(upload_dir)

            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={'REQUEST_METHOD': 'POST',
                         'CONTENT_TYPE': self.headers['Content-Type']}
            )

            if 'file' in form:
                file_item = form['file']
                if file_item.filename:
                    # SECURITY: Sanitize the filename to prevent path traversal
                    filename = os.path.basename(file_item.filename)
                    if not filename:
                        self._send_response(400, "Invalid filename provided.")
                        return

                    filepath = os.path.join(upload_dir, filename)
                    
                    # SECURITY: Double-check the final path
                    if not os.path.abspath(filepath).startswith(os.path.abspath(upload_dir)):
                        self._send_response(400, "Path traversal attempt detected.")
                        return

                    with open(filepath, 'wb') as f:
                        f.write(file_item.file.read())
                    
                    message = f"File '{filename}' uploaded successfully."
                    self._send_response(200, message)
                else:
                    self._send_response(400, "No file selected in form.")
            else:
                self._send_response(400, "Form is missing 'file' field.")
        else:
            self._send_response(404, "Not Found.")

    def _send_response(self, code, message):
        self.send_response(code)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(message.encode('utf-8'))

    def log_message(self, format, *args):
        # Suppress server logging for cleaner test output
        return


def run_server(port):
    server_address = ('', port)
    httpd = HTTPServer(server_address, UploadHandler)
    httpd.serve_forever()


if __name__ == '__main__':
    PORT = 8081
    UPLOAD_URL = f"http://localhost:{PORT}/upload"

    # Run the server in a separate thread
    server_thread = threading.Thread(target=run_server, args=(PORT,))
    server_thread.daemon = True
    server_thread.start()
    print(f"Test server started in background on port {PORT}")
    time.sleep(1) # Give server time to start

    # --- Test Cases ---
    temp_dir = "temp_test_files"
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)

    print("Running 5 test cases...")
    for i in range(1, 6):
        test_file_path = os.path.join(temp_dir, f"test_document_{i}.pdf")
        with open(test_file_path, "w") as f:
            f.write(f"This is a dummy PDF file for test {i}.")
        
        print(f"\n--- Test Case {i} ---")
        print(f"Uploading file: {test_file_path}")
        response = upload_pdf_file(UPLOAD_URL, test_file_path)
        if response:
            print(f"Status Code: {response.status_code}")
            print(f"Server Response: {response.text}")
        else:
            print("Upload failed.")

    # --- Cleanup ---
    print("\nCleaning up test files and directories...")
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
    if os.path.exists("uploads"):
        shutil.rmtree("uploads")
    print("Cleanup complete. The server thread will exit with the main program.")