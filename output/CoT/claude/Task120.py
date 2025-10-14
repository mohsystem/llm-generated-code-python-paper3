
import html
import cgi
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

class Task120:
    @staticmethod
    def encode_for_html(user_input):
        """Safely encode user input for HTML display"""
        if user_input is None:
            return ""
        # Use html.escape to prevent XSS attacks
        return html.escape(user_input, quote=True)
    
    @staticmethod
    def display_user_input(user_input):
        """Display user input safely in HTML format"""
        safe_input = Task120.encode_for_html(user_input)
        return f"""<html>\n<head>\n    <meta charset="UTF-8">\n    <title>User Input Display</title>\n</head>\n<body>\n    <h1>User Input Display</h1>\n    <p>You entered: {safe_input}</p>\n</body>\n</html>"""

class SecureHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urlparse(self.path)
        query_params = parse_qs(parsed_path.query)
        user_input = query_params.get('input', [''])[0]
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.end_headers()
        
        html_content = Task120.display_user_input(user_input)
        self.wfile.write(html_content.encode('utf-8'))
    
    def log_message(self, format, *args):
        pass  # Suppress log messages

def main():
    """Main method with test cases"""
    print("Test Case 1 - Normal input:")
    print(Task120.display_user_input("Hello World"))
    print()
    
    print("Test Case 2 - Input with HTML tags:")
    print(Task120.display_user_input("<script>alert('XSS')</script>"))
    print()
    
    print("Test Case 3 - Input with special characters:")
    print(Task120.display_user_input("Tom & Jerry's \"Adventure\""))
    print()
    
    print("Test Case 4 - Input with single quotes:")
    print(Task120.display_user_input("It's a beautiful day"))
    print()
    
    print("Test Case 5 - Input with mixed content:")
    print(Task120.display_user_input("<div>Hello</div> & <span>World</span>"))

if __name__ == "__main__":
    main()
