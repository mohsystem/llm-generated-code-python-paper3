
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, unquote
import html

class Task38(BaseHTTPRequestHandler):
    
    @staticmethod
    def sanitize_input(text):
        """Sanitize user input to prevent XSS attacks"""
        if text is None:
            return ""
        return html.escape(text)
    
    @staticmethod
    def get_form_html():
        return """<!DOCTYPE html>\n<html>\n<head>\n    <title>User Input Form</title>\n    <style>\n        body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }\n        input, textarea { width: 100%; padding: 10px; margin: 10px 0; box-sizing: border-box; }\n        button { background: #4CAF50; color: white; padding: 10px 20px; border: none; cursor: pointer; }\n        button:hover { background: #45a049; }\n    </style>\n</head>\n<body>\n    <h1>User Input Form</h1>\n    <form method="POST" action="/submit">\n        <label>Name:</label>\n        <input type="text" name="name" required><br>\n        <label>Message:</label>\n        <textarea name="message" rows="4" required></textarea><br>\n        <button type="submit">Submit</button>\n    </form>\n</body>\n</html>"""
    
    @staticmethod
    def get_response_html(name, message):
        safe_name = Task38.sanitize_input(name)
        safe_message = Task38.sanitize_input(message)
        return f"""<!DOCTYPE html>\n<html>\n<head>\n    <title>Your Response</title>\n    <style>\n        body {{ font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }}\n        .result {{ background: #f0f0f0; padding: 20px; border-radius: 5px; margin: 20px 0; }}\n        a {{ color: #4CAF50; text-decoration: none; }}\n    </style>\n</head>\n<body>\n    <h1>Your Submission</h1>\n    <div class="result">\n        <p><strong>Name:</strong> {safe_name}</p>\n        <p><strong>Message:</strong> {safe_message}</p>\n    </div>\n    <a href="/">← Back to Form</a>\n</body>\n</html>"""
    
    def do_GET(self):
        if self.path == '/' or self.path == '/index':
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(self.get_form_html().encode('utf-8'))
        else:
            self.send_response(404)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"<html><body><h1>404 Not Found</h1></body></html>")
    
    def do_POST(self):
        if self.path == '/submit':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            params = parse_qs(post_data)
            
            name = params.get('name', [''])[0]
            message = params.get('message', [''])[0]
            
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(self.get_response_html(name, message).encode('utf-8'))
        else:
            self.send_response(405)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Method Not Allowed</h1></body></html>")
    
    def log_message(self, format, *args):
        pass  # Suppress default logging

def main():
    print("Testing sanitize_input function with 5 test cases:\\n")
    
    test_cases = [
        "Hello World",
        "<script>alert('XSS')</script>",
        "Name with <b>HTML</b> tags",
        "Special chars: & < > \" '",
        "Normal text without special characters"
    ]
    
    for i, test in enumerate(test_cases, 1):
        print(f"Test Case {i}:")
        print(f"Input: {test}")
        print(f"Sanitized: {Task38.sanitize_input(test)}")
        print()
    
    print("\\nStarting web server on http://localhost:8000")
    print("Press Ctrl+C to stop the server\\n")
    
    server = HTTPServer(('localhost', 8000), Task38)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\\nServer stopped.")
        server.shutdown()

if __name__ == '__main__':
    main()
