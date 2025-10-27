
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
import hashlib
import secrets
import re

users = {}
sessions = {}
login_attempts = {}
MAX_ATTEMPTS = 5

def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

users['admin'] = hash_password('admin123')
users['user1'] = hash_password('password1')

def generate_session_token():
    return secrets.token_urlsafe(32)

class Lse52(BaseHTTPRequestHandler):
    def get_session(self):
        cookie = self.headers.get('Cookie')
        if cookie and 'session=' in cookie:
            for part in cookie.split(';'):
                if part.strip().startswith('session='):
                    return part.strip()[8:]
        return None
    
    def is_authenticated(self):
        session_token = self.get_session()
        return session_token and session_token in sessions
    
    def send_html_response(self, code, content):
        self.send_response(code)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.end_headers()
        self.wfile.write(content.encode('utf-8'))
    
    def do_GET(self):
        if self.path == '/':
            self.handle_index()
        elif self.path == '/login':
            self.handle_login_get()
        elif self.path == '/secret':
            self.handle_secret()
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_POST(self):
        if self.path == '/login':
            self.handle_login_post()
        else:
            self.send_response(404)
            self.end_headers()
    
    def handle_index(self):
        html = """<!DOCTYPE html><html><head><title>Index</title></head><body>\n                 <h1>Welcome</h1><a href='/login'>Login</a></body></html>"""
        self.send_html_response(200, html)
    
    def handle_login_get(self):
        html = """<!DOCTYPE html><html><head><title>Login</title></head><body>\n                 <h1>Login</h1><form method='POST' action='/login'>\n                 <input type='text' name='username' placeholder='Username' required pattern='[a-zA-Z0-9]+' maxlength='50'/><br/>\n                 <input type='password' name='password' placeholder='Password' required maxlength='100'/><br/>\n                 <button type='submit'>Login</button></form></body></html>"""
        self.send_html_response(200, html)
    
    def handle_login_post(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        params = parse_qs(post_data)
        
        username = params.get('username', [''])[0]
        password = params.get('password', [''])[0]
        
        if not username or not password or not re.match(r'^[a-zA-Z0-9]+$', username) or len(username) > 50:
            self.send_html_response(400, "Invalid input")
            return
        
        client_ip = self.client_address[0]
        attempts = login_attempts.get(client_ip, 0)
        
        if attempts >= MAX_ATTEMPTS:
            self.send_html_response(429, "Too many login attempts. Try again later.")
            return
        
        hashed_password = hash_password(password)
        if username in users and users[username] == hashed_password:
            session_token = generate_session_token()
            sessions[session_token] = username
            login_attempts.pop(client_ip, None)
            
            self.send_response(302)
            self.send_header('Set-Cookie', f'session={session_token}; HttpOnly; SameSite=Strict; Path=/')
            self.send_header('Location', '/secret')
            self.end_headers()
        else:
            login_attempts[client_ip] = attempts + 1
            self.send_html_response(401, "Invalid credentials")
    
    def handle_secret(self):
        if not self.is_authenticated():
            self.send_response(302)
            self.send_header('Location', '/login')
            self.end_headers()
            return
        
        html = """<!DOCTYPE html><html><head><title>Secret</title></head><body>\n                 <h1>Secret settings</h1></body></html>"""
        self.send_html_response(200, html)

if __name__ == '__main__':
    server = HTTPServer(('localhost', 8000), Lse52)
    print("Server started on port 8000")
    print("Test cases:")
    print("1. Visit http://localhost:8000/ - should show index with login link")
    print("2. Click login link - should show login form")
    print("3. Login with admin/admin123 - should redirect to secret page")
    print("4. Try accessing /secret without login - should redirect to login")
    print("5. Login with wrong credentials - should show error")
    server.serve_forever()
