
from http.server import HTTPServer, BaseHTTPRequestHandler
import hashlib
import secrets
import urllib.parse
import html
from typing import Dict, Optional, Tuple
import time

# Secure session storage with expiration
sessions: Dict[str, Tuple[str, float]] = {}
# Store hashed passwords with salt
users: Dict[str, Tuple[bytes, bytes]] = {}
# Rate limiting for login attempts
login_attempts: Dict[str, Tuple[int, float]] = {}

SESSION_TIMEOUT = 1800  # 30 minutes in seconds
MAX_LOGIN_ATTEMPTS = 5
RATE_LIMIT_WINDOW = 300  # 5 minutes in seconds


def hash_password(password: str, salt: bytes) -> bytes:
    """Hash password with salt using SHA-256 and multiple iterations."""
    # Use PBKDF2 for key derivation with high iteration count
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return pwd_hash


def create_user(username: str, password: str) -> None:
    """Create a new user with securely hashed password."""
    # Generate unique random salt using secrets module (CSPRNG)
    salt = secrets.token_bytes(16)
    pwd_hash = hash_password(password, salt)
    users[username] = (pwd_hash, salt)


def verify_password(username: str, password: str) -> bool:
    """Verify password against stored hash."""
    if username not in users:
        return False
    stored_hash, salt = users[username]
    pwd_hash = hash_password(password, salt)
    # Constant-time comparison to prevent timing attacks
    return secrets.compare_digest(pwd_hash, stored_hash)


def generate_session_token() -> str:
    """Generate secure random session token."""
    return secrets.token_urlsafe(32)


def validate_session(token: Optional[str]) -> Optional[str]:
    """Validate session token and return username if valid."""
    if not token:
        return None
    if token not in sessions:
        return None
    username, expiry = sessions[token]
    if time.time() > expiry:
        # Clean up expired session
        del sessions[token]
        return None
    return username


def is_rate_limited(username: str) -> bool:
    """Check if user is rate limited."""
    if username not in login_attempts:
        return False
    attempts, last_attempt = login_attempts[username]
    time_since_last = time.time() - last_attempt
    if time_since_last > RATE_LIMIT_WINDOW:
        del login_attempts[username]
        return False
    return attempts >= MAX_LOGIN_ATTEMPTS


def record_login_attempt(username: str, success: bool) -> None:
    """Record login attempt for rate limiting."""
    if success:
        if username in login_attempts:
            del login_attempts[username]
    else:
        if username in login_attempts:
            attempts, _ = login_attempts[username]
            login_attempts[username] = (attempts + 1, time.time())
        else:
            login_attempts[username] = (1, time.time())


class SecureHTTPRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler with secure session management."""

    def do_GET(self) -> None:
        """Handle GET requests."""
        if self.path == '/':
            self.handle_index()
        elif self.path == '/login':
            self.handle_login_get()
        elif self.path == '/secret':
            self.handle_secret()
        else:
            self.send_error(404, "Not Found")

    def do_POST(self) -> None:
        """Handle POST requests."""
        if self.path == '/login':
            self.handle_login_post()
        else:
            self.send_error(405, "Method Not Allowed")

    def handle_index(self) -> None:
        """Render index page."""
        response = (
            '<!DOCTYPE html><html><head><meta charset="UTF-8">'
            '<title>Index</title></head><body>'
            '<h1>Welcome</h1><p><a href="/login">Login</a></p>'
            '</body></html>'
        )
        self.send_response_with_headers(200, response)

    def handle_login_get(self) -> None:
        """Render login form."""
        response = (
            '<!DOCTYPE html><html><head><meta charset="UTF-8">'
            '<title>Login</title></head><body><h1>Login</h1>'
            '<form method="POST" action="/login">'
            '<label>Username: <input type="text" name="username" '
            'required maxlength="50" pattern="[a-zA-Z0-9_]+"></label><br>'
            '<label>Password: <input type="password" name="password" '
            'required maxlength="100"></label><br>'
            '<button type="submit">Login</button></form></body></html>'
        )
        self.send_response_with_headers(200, response)

    def handle_login_post(self) -> None:
        """Process login form submission."""
        # Validate Content-Length to prevent excessive data
        content_length_str = self.headers.get('Content-Length', '0')
        try:
            content_length = int(content_length_str)
        except ValueError:
            self.send_error_response("Invalid request")
            return

        if content_length > 4096:  # Maximum request size
            self.send_error(413, "Request Entity Too Large")
            return

        # Read request body with length validation
        post_data = self.rfile.read(content_length).decode('utf-8')
        params = urllib.parse.parse_qs(post_data)

        # Extract and validate parameters
        username_list = params.get('username', [''])
        password_list = params.get('password', [''])

        if not username_list or not password_list:
            self.send_error_response("Missing credentials")
            return

        username = username_list[0]
        password = password_list[0]

        # Input validation
        if not username or not password:
            self.send_error_response("Invalid input")
            return

        if len(username) > 50 or len(password) > 100:
            self.send_error_response("Input too long")
            return

        # Sanitize username to alphanumeric only
        if not username.replace('_', '').isalnum():
            self.send_error_response("Invalid username format")
            return

        # Check rate limiting
        if is_rate_limited(username):
            self.send_error_response("Too many login attempts. Please try again later.")
            return

        # Verify credentials
        valid = verify_password(username, password)
        record_login_attempt(username, valid)

        if valid:
            # Create session with secure token
            token = generate_session_token()
            expiry = time.time() + SESSION_TIMEOUT
            sessions[token] = (username, expiry)

            # Set secure cookie and redirect
            self.send_response(302)
            self.send_header('Location', '/secret')
            self.send_header('Set-Cookie',
                           f'session={token}; HttpOnly; Secure; '
                           f'SameSite=Strict; Max-Age={SESSION_TIMEOUT}; Path=/')
            self.send_secure_headers()
            self.end_headers()
        else:
            self.send_error_response("Invalid credentials")

    def handle_secret(self) -> None:
        """Render secret page (requires authentication)."""
        # Get session token from cookie
        cookie = self.headers.get('Cookie', '')
        token = None
        for c in cookie.split(';'):
            c = c.strip()
            if c.startswith('session='):
                token = c[8:]
                break

        username = validate_session(token)

        if not username:
            # Redirect to login if not authenticated
            self.send_response(302)
            self.send_header('Location', '/login')
            self.send_secure_headers()
            self.end_headers()
            return

        # Escape username to prevent XSS
        safe_username = html.escape(username)
        response = (
            '<!DOCTYPE html><html><head><meta charset="UTF-8">'
            '<title>Secret</title></head><body>'
            '<h1>Secret settings</h1>'
            f'<p>Welcome, {safe_username}!</p>'
            '<p><a href="/">Home</a></p></body></html>'
        )
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
        self.send_secure_headers()
        self.end_headers()
        self.wfile.write(response.encode('utf-8'))

    def send_response_with_headers(self, code: int, content: str) -> None:
        """Send HTTP response with security headers."""
        self.send_response(code)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.send_secure_headers()
        self.end_headers()
        self.wfile.write(content.encode('utf-8'))

    def send_secure_headers(self) -> None:
        """Send security-related HTTP headers."""
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Content-Security-Policy', "default-src 'self'")

    def send_error_response(self, message: str) -> None:
        """Send error response with escaped message."""
        safe_message = html.escape(message)
        response = (
            '<!DOCTYPE html><html><head><meta charset="UTF-8">'
            '<title>Login Error</title></head><body>'
            f'<h1>Error</h1><p>{safe_message}</p>'
            '<p><a href="/login">Try again</a></p></body></html>'
        )
        self.send_response(401)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.send_secure_headers()
        self.end_headers()
        self.wfile.write(response.encode('utf-8'))

    def log_message(self, format: str, *args) -> None:
        """Override to prevent logging sensitive information."""
        # Only log non-sensitive request info
        pass


def main():
    """Main entry point - create test users and start server."""
    # Create test users with secure password hashing and unique salts
    create_user('admin', 'SecureP@ss123!')
    create_user('user1', 'TestUser#456')
    create_user('user2', 'Demo$Pass789')
    create_user('testuser', 'MyTest&Pass000')
    create_user('guest', 'Guest!Pass321')

    server_address = ('', 8000)
    httpd = HTTPServer(server_address, SecureHTTPRequestHandler)

    print('Server started on port 8000')
    print('Test users created:')
    print('  admin / SecureP@ss123!')
    print('  user1 / TestUser#456')
    print('  user2 / Demo$Pass789')
    print('  testuser / MyTest&Pass000')
    print('  guest / Guest!Pass321')

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print('\\nShutting down server...')
        httpd.shutdown()


if __name__ == '__main__':
    main()
