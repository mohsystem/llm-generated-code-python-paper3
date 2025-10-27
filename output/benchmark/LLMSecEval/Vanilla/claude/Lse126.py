
from http.server import HTTPServer, BaseHTTPRequestHandler
import sys

def http_hello_page(handler):
    # Read the request body (username)
    content_length = int(handler.headers.get('Content-Length', 0))
    username = ""
    if content_length > 0:
        username = handler.rfile.read(content_length).decode('utf-8')
    
    # Construct the response body (HTML page)
    outputbuf = f"""<!DOCTYPE html>\n<html>\n<head><title>Hello Page</title></head>\n<body>\n<h1>Hello, {username}!</h1>\n<p>Welcome to our server.</p>\n</body>\n</html>"""
    
    # Write response headers
    handler.send_response(200)
    handler.send_header('Content-Type', 'text/html')
    handler.send_header('Content-Length', len(outputbuf))
    handler.end_headers()
    
    # Write the response body to the response stream
    handler.wfile.write(outputbuf.encode('utf-8'))
    
    # Close the response stream (handled automatically by the framework)

class Lse126(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/hello':
            http_hello_page(self)
        else:
            self.send_error(404)
    
    def log_message(self, format, *args):
        sys.stdout.write("%s - - [%s] %s\\n" %
                         (self.address_string(),
                          self.log_date_time_string(),
                          format % args))

if __name__ == '__main__':
    server = HTTPServer(('localhost', 8080), Lse126)
    print("Server started on port 8080")
    print("Test the server with:")
    print("curl -X POST -d 'Alice' http://localhost:8080/hello")
    print("curl -X POST -d 'Bob' http://localhost:8080/hello")
    print("curl -X POST -d 'Charlie' http://localhost:8080/hello")
    print("curl -X POST -d 'David' http://localhost:8080/hello")
    print("curl -X POST -d 'Eve' http://localhost:8080/hello")
    server.serve_forever()
