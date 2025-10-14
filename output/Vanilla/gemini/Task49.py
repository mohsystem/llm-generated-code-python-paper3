import http.server
import socketserver
import json
import threading
import time
import urllib.request

# In-memory database
user_database = []

class UserAPIHandler(http.server.BaseHTTPRequestHandler):
    """
    Handles API requests for user data.
    """
    def do_POST(self):
        if self.path == '/api/users':
            try:
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                user_data = json.loads(post_data.decode('utf-8'))

                # Basic validation
                if 'name' not in user_data or 'email' not in user_data:
                    self.send_response(400) # Bad Request
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "Missing name or email"}).encode('utf-8'))
                    return
                
                # Store data
                user_database.append(user_data)
                
                # Send success response
                self.send_response(201) # Created
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                response = {"message": "User created successfully", "user": user_data}
                self.wfile.write(json.dumps(response).encode('utf-8'))

            except json.JSONDecodeError:
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Invalid JSON"}).encode('utf-8'))
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'Not Found')

def run_server(port):
    """Starts the HTTP server."""
    handler = UserAPIHandler
    # Allows address reuse to avoid "Address already in use" errors on quick restarts
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", port), handler) as httpd:
        print(f"Server started on port {port}")
        httpd.serve_forever()

def run_tests(port):
    """Runs test cases against the server."""
    print("Running 5 test cases...")
    test_cases = [
        {"name": "Alice", "email": "alice@example.com"},
        {"name": "Bob", "email": "bob@example.com"},
        {"name": "Charlie", "email": "charlie@example.com"},
        {"name": "David", "email": "david@example.com"},
        {"name": "Eve", "email": "eve@example.com"}
    ]

    for user in test_cases:
        try:
            url = f"http://localhost:{port}/api/users"
            data = json.dumps(user).encode('utf-8')
            req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'}, method='POST')
            with urllib.request.urlopen(req) as response:
                print(f"POST with {user}... Response: {response.getcode()}")
        except Exception as e:
            print(f"Request failed for {user}: {e}")

def main():
    """Main function to run server and tests."""
    port = 8081
    
    # Run the server in a separate thread
    server_thread = threading.Thread(target=run_server, args=(port,))
    server_thread.daemon = True # Allows main thread to exit even if server thread is running
    server_thread.start()
    
    # Give the server a moment to start up
    time.sleep(1)

    # Run tests
    run_tests(port)
    
    print("\n--- Current Database State ---")
    print(json.dumps(user_database, indent=2))
    print("----------------------------")
    print("Test cases finished. Server is still running. Press Ctrl+C to stop.")

    # Keep the main thread alive to let the server run
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nServer shutting down.")

if __name__ == "__main__":
    main()