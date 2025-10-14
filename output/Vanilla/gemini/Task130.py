import http.server
import socketserver
import json

PORT = 8000

class CORSRequestHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204) # No Content
        self.end_headers()

    def do_GET(self):
        if self.path == '/api/data':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            response = {
                "message": "Hello from Python API with CORS!"
            }
            self.wfile.write(json.dumps(response).encode('utf-8'))
        else:
            # Fallback to serving files from the current directory
            super().do_GET()

def main():
    with socketserver.TCPServer(("", PORT), CORSRequestHandler) as httpd:
        print(f"Python server started on port {PORT}")
        print(f"API endpoint available at http://localhost:{PORT}/api/data")

        # --- Test Cases ---
        print("\n--- How to Test (run from another terminal) ---")
        print("1. Test Preflight (OPTIONS request):")
        print(f"   curl -v -X OPTIONS http://localhost:{PORT}/api/data -H \"Origin: http://example.com\" -H \"Access-Control-Request-Method: GET\"")
        print("\n2. Test Actual Request from an allowed origin:")
        print(f"   curl -v -H \"Origin: http://example.com\" http://localhost:{PORT}/api/data")
        print("\n3. Test with a different allowed origin (since we use '*'):")
        print(f"   curl -v -H \"Origin: http://another-site.com\" http://localhost:{PORT}/api/data")
        print("\n4. Test a non-CORS request (no Origin header):")
        print(f"   curl -v http://localhost:{PORT}/api/data")
        print("\n5. Test with a browser. Create an HTML file with the following JS and open it:")
        print(f"   fetch('http://localhost:{PORT}/api/data').then(r => r.json()).then(console.log).catch(console.error);")
        
        httpd.serve_forever()

if __name__ == "__main__":
    main()