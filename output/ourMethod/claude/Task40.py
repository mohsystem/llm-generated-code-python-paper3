
import secrets
import hmac
import hashlib
import re
from typing import Dict, Optional, Tuple
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, unquote
import html

SECRET_KEY = secrets.token_bytes(32)
session_tokens: Dict[str, str] = {}
user_settings: Dict[str, Dict[str, str]] = {}

MAX_USERNAME_LENGTH = 50
MAX_EMAIL_LENGTH = 100
MAX_THEME_LENGTH = 20

def generate_csrf_token(session_id: str) -> str:
    token = secrets.token_urlsafe(32)
    signature = hmac.new(
        SECRET_KEY,
        f"{session_id}:{token}".encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    csrf_token = f"{token}.{signature}"
    session_tokens[session_id] = csrf_token
    return csrf_token

def validate_csrf_token(session_id: str, token: str) -> bool:
    if not session_id or not token:
        return False
    
    stored_token = session_tokens.get(session_id)
    if not stored_token:
        return False
    
    return constant_time_compare(stored_token, token)

def constant_time_compare(a: str, b: str) -> bool:
    if not a or not b:
        return False
    
    a_bytes = a.encode('utf-8')
    b_bytes = b.encode('utf-8')
    
    if len(a_bytes) != len(b_bytes):
        return False
    
    result = 0
    for x, y in zip(a_bytes, b_bytes):
        result |= x ^ y
    return result == 0

def sanitize_input(input_str: Optional[str], max_length: int) -> str:
    if not input_str:
        return ""
    input_str = input_str.strip()
    if len(input_str) > max_length:
        input_str = input_str[:max_length]
    return re.sub(r'[<>"\'&]', '', input_str)

def is_valid_email(email: str) -> bool:
    if not email:
        return False
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$'
    return bool(re.match(email_regex, email)) and len(email) <= MAX_EMAIL_LENGTH

def update_user_settings(
    session_id: str,
    csrf_token: str,
    username: str,
    email: str,
    theme: str
) -> str:
    if not validate_csrf_token(session_id, csrf_token):
        return "Error: Invalid CSRF token"
    
    username = sanitize_input(username, MAX_USERNAME_LENGTH)
    email = sanitize_input(email, MAX_EMAIL_LENGTH)
    theme = sanitize_input(theme, MAX_THEME_LENGTH)
    
    if not username:
        return "Error: Username cannot be empty"
    
    if not is_valid_email(email):
        return "Error: Invalid email format"
    
    if theme not in ['light', 'dark', 'auto']:
        return "Error: Invalid theme selection"
    
    user_settings[session_id] = {
        'username': username,
        'email': email,
        'theme': theme
    }
    
    if session_id in session_tokens:
        del session_tokens[session_id]
    
    return "Success: Settings updated successfully"

class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        session_id = secrets.token_urlsafe(32)
        csrf_token = generate_csrf_token(session_id)
        
        response = self.build_form(session_id, csrf_token)
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(response.encode('utf-8'))
    
    def do_POST(self) -> None:
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > 8192:
            self.send_response(413)
            self.end_headers()
            return
        
        body = self.rfile.read(content_length).decode('utf-8')
        params = self.parse_form_data(body)
        
        session_id = params.get('sessionId', '')
        csrf_token = params.get('csrf_token', '')
        username = params.get('username', '')
        email = params.get('email', '')
        theme = params.get('theme', '')
        
        result = update_user_settings(session_id, csrf_token, username, email, theme)
        
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.end_headers()
        self.wfile.write(result.encode('utf-8'))
    
    def build_form(self, session_id: str, csrf_token: str) -> str:
        return f"""<!DOCTYPE html>\n<html>\n<head><title>User Settings</title></head>\n<body>\n<h2>Update User Settings</h2>\n<form method='POST' action='/'>\n<input type='hidden' name='sessionId' value='{html.escape(session_id)}'>\n<input type='hidden' name='csrf_token' value='{html.escape(csrf_token)}'>\n<label>Username: <input type='text' name='username' maxlength='50' required></label><br>\n<label>Email: <input type='email' name='email' maxlength='100' required></label><br>\n<label>Theme: <select name='theme'>\n<option value='light'>Light</option>\n<option value='dark'>Dark</option>\n<option value='auto'>Auto</option>\n</select></label><br>\n<button type='submit'>Update Settings</button>\n</form>\n</body>\n</html>"""
    
    def parse_form_data(self, body: str) -> Dict[str, str]:
        params = {}
        pairs = body.split('&')
        for pair in pairs:
            if '=' in pair:
                key, value = pair.split('=', 1)
                params[unquote(key)] = unquote(value)
        return params
    
    def log_message(self, format: str, *args) -> None:
        pass

def main() -> None:
    print("Test Case 1: Valid CSRF token")
    session1 = "session1"
    token1 = generate_csrf_token(session1)
    result1 = update_user_settings(session1, token1, "john_doe", "john@example.com", "dark")
    print(result1)
    
    print("\\nTest Case 2: Invalid CSRF token")
    session2 = "session2"
    generate_csrf_token(session2)
    result2 = update_user_settings(session2, "invalid_token", "jane_doe", "jane@example.com", "light")
    print(result2)
    
    print("\\nTest Case 3: Invalid email format")
    session3 = "session3"
    token3 = generate_csrf_token(session3)
    result3 = update_user_settings(session3, token3, "bob", "invalid-email", "auto")
    print(result3)
    
    print("\\nTest Case 4: Empty username")
    session4 = "session4"
    token4 = generate_csrf_token(session4)
    result4 = update_user_settings(session4, token4, "", "alice@example.com", "light")
    print(result4)
    
    print("\\nTest Case 5: Invalid theme")
    session5 = "session5"
    token5 = generate_csrf_token(session5)
    result5 = update_user_settings(session5, token5, "charlie", "charlie@example.com", "invalid_theme")
    print(result5)
    
    server = HTTPServer(('localhost', 8080), RequestHandler)
    print("\\nServer started on port 8080")
    server.serve_forever()

if __name__ == "__main__":
    main()
