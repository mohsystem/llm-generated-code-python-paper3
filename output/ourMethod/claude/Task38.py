
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, unquote_plus
import re
from typing import Optional

MAX_INPUT_LENGTH = 1000
SAFE_INPUT_PATTERN = re.compile(r"^[a-zA-Z0-9\\s.,!?'-]*$")

def sanitize_input(user_input: Optional[str]) -> str:
    if user_input is None:
        return ""
    
    if len(user_input) > MAX_INPUT_LENGTH:
        user_input = user_input[:MAX_INPUT_LENGTH]
    
    if not SAFE_INPUT_PATTERN.match(user_input):
        return ""
    
    return escape_html(user_input)

def escape_html(text: Optional[str]) -> str:
    if text is None:
        return ""
    
    html_escape_table = {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#x27;"
    }
    
    return "".join(html_escape_table.get(c, c) for c in text)

def process_user_input(user_input: str) -> str:
    return sanitize_input(user_input)

class SecureRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            response = """<!DOCTYPE html>\n<html>\n<head>\n    <meta charset="UTF-8">\n    <title>Form</title>\n</head>\n<body>\n    <h1>User Input Form</h1>\n    <form method="POST" action="/submit">\n        <label>Enter text:</label><br>\n        <input type="text" name="userInput" maxlength="1000" required><br><br>\n        <input type="submit" value="Submit">\n    </form>\n</body>\n</html>"""
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(response.encode('utf-8'))))
            self.end_headers()
            self.wfile.write(response.encode('utf-8'))
        else:
            self.send_error(404)
    
    def do_POST(self):
        if self.path == "/submit":
            content_length = int(self.headers.get('Content-Length', 0))
            
            if content_length > MAX_INPUT_LENGTH + 100:
                self.send_error(400)
                return
            
            post_data = self.rfile.read(content_length).decode('utf-8')
            params = parse_qs(post_data)
            user_input = params.get('userInput', [''])[0]
            
            sanitized = sanitize_input(user_input)
            
            response = f"""<!DOCTYPE html>\n<html>\n<head>\n    <meta charset="UTF-8">\n    <title>Result</title>\n</head>\n<body>\n    <h1>Your Input:</h1>\n    <p>{sanitized}</p>\n    <a href="/">Back to form</a>\n</body>\n</html>"""
            
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(response.encode('utf-8'))))
            self.end_headers()
            self.wfile.write(response.encode('utf-8'))
        else:
            self.send_error(404)
    
    def log_message(self, format, *args):
        pass

def main():
    print("Test 1:", process_user_input("Hello World"))
    print("Test 2:", process_user_input("Test123"))
    print("Test 3:", process_user_input("<script>alert('xss')</script>"))
    print("Test 4:", process_user_input("Valid input with spaces!"))
    print("Test 5:", process_user_input("a" * 1500))
    
    server = HTTPServer(('localhost', 8080), SecureRequestHandler)
    print("Server started on port 8080")
    server.serve_forever()

if __name__ == "__main__":
    main()
