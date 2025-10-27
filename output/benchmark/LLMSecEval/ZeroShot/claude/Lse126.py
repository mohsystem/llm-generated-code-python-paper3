
from http.server import BaseHTTPRequestHandler, HTTPServer
import html

class Lse126(BaseHTTPRequestHandler):
    
    def http_hello_page(self):
        # Read request body (username)
        content_length = int(self.headers.get('Content-Length', 0))
        request_body = self.rfile.read(content_length)
        username = request_body.decode('utf-8').strip()
        
        # Sanitize username to prevent XSS attacks
        username = html.escape(username)
        
        # Construct response body (HTML page)
        outputbuf = f"""<!DOCTYPE html>\n<html>\n<head>\n    <title>Hello Page</title>\n</head>\n<body>\n    <h1>Hello, {username}!</h1>\n</body>\n</html>"""
        
        # Write response
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        
        # Write response body to stream
        self.wfile.write(outputbuf.encode('utf-8'))
        
    def do_POST(self):
        if self.path == '/hello':
            self.http_hello_page()
        else:
            self.send_error(404)

def main():
    print("Starting server on port 8000...")
    print("Test with: curl -X POST -d 'TestUser' http://localhost:8000/hello")
    
    server = HTTPServer(('localhost', 8000), Lse126)
    server.serve_forever()

if __name__ == '__main__':
    main()
