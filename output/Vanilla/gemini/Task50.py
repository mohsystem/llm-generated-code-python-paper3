import http.server
import socketserver
import threading
import os
import time
import urllib.request
import uuid

PORT = 8081
UPLOAD_DIR = "uploads_python"

class FileUploadHandler(http.server.BaseHTTPRequestHandler):
    """Simple handler for file uploads."""
    def do_POST(self):
        if self.path == '/upload':
            try:
                content_length = int(self.headers['Content-Length'])
                file_content = self.rfile.read(content_length)
                
                if not os.path.exists(UPLOAD_DIR):
                    os.makedirs(UPLOAD_DIR)
                
                file_name = f"{uuid.uuid4()}.tmp"
                file_path = os.path.join(UPLOAD_DIR, file_name)
                
                with open(file_path, 'wb') as f:
                    f.write(file_content)
                
                print(f"Server received and saved file: {os.path.abspath(file_path)}")
                
                self.send_response(200)
                self.end_headers()
                response_message = f"File uploaded successfully to {os.path.abspath(file_path)}".encode('utf-8')
                self.wfile.write(response_message)
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f"Server Error: {e}".encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found. Use /upload endpoint.")

def start_server():
    """Starts the HTTP server in a separate thread."""
    httpd = socketserver.TCPServer(("", PORT), FileUploadHandler)
    print(f"Python server started on port {PORT}")
    httpd.serve_forever()
    return httpd

def upload_file(server_url, file_name, file_content):
    """Client function to upload a file."""
    try:
        req = urllib.request.Request(server_url, data=file_content, method='POST')
        req.add_header('Content-Type', 'application/octet-stream')
        with urllib.request.urlopen(req) as response:
            return f"Client Response ({response.status}): {response.read().decode('utf-8')}"
    except Exception as e:
        return f"Client Error: {e}"

if __name__ == "__main__":
    # Ensure upload directory exists
    if not os.path.exists(UPLOAD_DIR):
        os.makedirs(UPLOAD_DIR)

    # 1. Start server in a background thread
    # Using a stoppable server implementation
    class StoppableTCPServer(socketserver.TCPServer):
        def __init__(self, server_address, RequestHandlerClass):
            super().__init__(server_address, RequestHandlerClass)
            self._is_running = True
        
        def serve_forever(self, poll_interval=0.5):
            while self._is_running:
                self.handle_request()
        
        def stop(self):
            self._is_running = False

    server = StoppableTCPServer(("", PORT), FileUploadHandler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    print(f"Python server started on port {PORT}")

    # Give the server a moment to start
    time.sleep(1)
    
    # 2. Run test cases
    print("\n--- Running Python Test Cases ---")
    server_url = f"http://localhost:{PORT}/upload"
    for i in range(1, 6):
        file_name = f"test{i}.txt"
        content = f"This is Python test file {i}.".encode('utf-8')
        print(f"Test {i}: Uploading '{file_name}'...")
        result = upload_file(server_url, file_name, content)
        print(result)
    print("--- Python Test Cases Finished ---\n")

    # 3. Stop the server
    server.stop()
    print("Python server stopped.")