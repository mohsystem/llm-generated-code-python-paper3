
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, unquote
import secrets
import html
import re

class Task38:
    csrf_tokens = {}

    @staticmethod
    def generate_csrf_token():
        token = secrets.token_urlsafe(32)
        Task38.csrf_tokens[token] = "valid"
        return token

    @staticmethod
    def escape_html(text):
        if text is None:
            return ""
        return html.escape(text, quote=True)

    @staticmethod
    def sanitize_input(input_str, max_length):
        if input_str is None:
            return ""
        input_str = input_str.strip()
        if len(input_str) > max_length:
            input_str = input_str[:max_length]
        return input_str

    @staticmethod
    def is_valid_email(email):
        pattern = r'^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$'
        return email and re.match(pattern, email) is not None

class SecureFormHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            csrf_token = Task38.generate_csrf_token()
            html_content = f"""<!DOCTYPE html>\n<html><head><meta charset='UTF-8'>\n<title>Secure Form</title></head><body>\n<h1>User Input Form</h1>\n<form method='POST' action='/submit'>\n<input type='hidden' name='csrf_token' value='{Task38.escape_html(csrf_token)}'>\n<label>Name: <input type='text' name='name' maxlength='100' required></label><br>\n<label>Email: <input type='email' name='email' maxlength='100' required></label><br>\n<label>Message: <textarea name='message' maxlength='500' required></textarea></label><br>\n<input type='submit' value='Submit'>\n</form></body></html>"""
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Frame-Options', 'DENY')
            self.send_header('X-XSS-Protection', '1; mode=block')
            self.end_headers()
            self.wfile.write(html_content.encode('utf-8'))
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path == '/submit':
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length).decode('utf-8')
            params = parse_qs(post_data)
            
            csrf_token = params.get('csrf_token', [''])[0]
            if not csrf_token or csrf_token not in Task38.csrf_tokens:
                self.send_error(403, "Invalid CSRF token")
                return
            del Task38.csrf_tokens[csrf_token]
            
            name = Task38.sanitize_input(params.get('name', [''])[0], 100)
            email = Task38.sanitize_input(params.get('email', [''])[0], 100)
            message = Task38.sanitize_input(params.get('message', [''])[0], 500)
            
            if not Task38.is_valid_email(email):
                self.send_error(400, "Invalid email format")
                return
            
            html_content = f"""<!DOCTYPE html>\n<html><head><meta charset='UTF-8'>\n<title>Form Submission Result</title></head><body>\n<h1>Your Submitted Data</h1>\n<p><strong>Name:</strong> {Task38.escape_html(name)}</p>\n<p><strong>Email:</strong> {Task38.escape_html(email)}</p>\n<p><strong>Message:</strong> {Task38.escape_html(message)}</p>\n<a href='/'>Back to Form</a></body></html>"""
            
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Frame-Options', 'DENY')
            self.send_header('X-XSS-Protection', '1; mode=block')
            self.end_headers()
            self.wfile.write(html_content.encode('utf-8'))
        else:
            self.send_error(404)

    def log_message(self, format, *args):
        pass

if __name__ == '__main__':
    server = HTTPServer(('localhost', 8080), SecureFormHandler)
    print("Server started on port 8080")
    server.serve_forever()
