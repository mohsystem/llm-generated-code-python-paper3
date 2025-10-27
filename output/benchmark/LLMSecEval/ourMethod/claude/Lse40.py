
from http.server import BaseHTTPRequestHandler, HTTPServer
import html
import time
import secrets
from typing import Dict, Optional

# Secure session storage with timeout
sessions: Dict[str, 'SessionData'] = {}
SESSION_TIMEOUT = 30 * 60  # 30 minutes in seconds

class SessionData:
    """Secure session data container with expiration"""
    def __init__(self, username: str, email: str, ssn: str):
        self.username = username
        self.email = email
        self.ssn = ssn  # In production, encrypt this value
        self.last_access = time.time()
    
    def is_expired(self) -> bool:
        """Check if session has expired"""
        return time.time() - self.last_access > SESSION_TIMEOUT
    
    def update_access(self):
        """Update last access timestamp"""
        self.last_access = time.time()

def get_last_four_digits(ssn: str) -> str:
    """\n    Securely extract last 4 digits of SSN.\n    Returns masked value if invalid.\n    """
    if not ssn or len(ssn) < 4:
        return "****"
    # Only return last 4 digits
    return ssn[-4:]

def is_valid_ssn(ssn: str) -> bool:
    """\n    Validate SSN format (XXX-XX-XXXX or XXXXXXXXX).\n    Basic validation for demonstration.\n    """
    if not ssn:
        return False
    cleaned = ssn.replace("-", "")
    return cleaned.isdigit() and len(cleaned) == 9

def sanitize_output(text: str) -> str:
    """\n    Sanitize text for HTML output to prevent XSS.\n    Uses html.escape for comprehensive protection.\n    """
    if text is None:
        return ""
    return html.escape(text, quote=True)

class InfoHandler(BaseHTTPRequestHandler):
    """HTTP request handler for /info endpoint"""
    
    def log_message(self, format, *args):
        """Override to prevent logging sensitive information"""
        pass  # Suppress default logging
    
    def get_session_id(self) -> Optional[str]:
        """Extract session ID from Cookie header"""
        cookie = self.headers.get('Cookie')
        if cookie and cookie.startswith('sessionId='):
            return cookie[10:]
        return None
    
    def send_error_response(self, code: int, message: str):
        """Send error response with security headers"""
        self.send_response(code)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(message.encode('utf-8'))
    
    def do_GET(self):
        """Handle GET requests to /info endpoint"""
        # Only handle /info path
        if self.path != '/info':
            self.send_error_response(404, "Not Found")
            return
        
        # Retrieve session ID from cookie
        session_id = self.get_session_id()
        
        if not session_id or session_id not in sessions:
            self.send_error_response(401, "Unauthorized: No valid session found")
            return
        
        session = sessions[session_id]
        
        # Check if session expired
        if session.is_expired():
            del sessions[session_id]
            self.send_error_response(401, "Unauthorized: Session expired")
            return
        
        # Update session access time
        session.update_access()
        
        # Sanitize all output to prevent XSS
        safe_username = sanitize_output(session.username)
        safe_email = sanitize_output(session.email)
        last_four = get_last_four_digits(session.ssn)
        
        # Build secure HTML response
        response_body = f"""<!DOCTYPE html>\n<html>\n<head>\n    <meta charset="UTF-8">\n    <title>User Info</title>\n</head>\n<body>\n    <h1>User Information</h1>\n    <p>Username: {safe_username}</p>\n    <p>Email: {safe_email}</p>\n    <p>SSN (last 4): ***-**-{last_four}</p>\n</body>\n</html>"""
        
        # Send response with security headers
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Content-Security-Policy', "default-src 'self'")
        self.end_headers()
        self.wfile.write(response_body.encode('utf-8'))

def create_session(username: str, email: str, ssn: str) -> str:
    """\n    Create a new session with validated data.\n    Returns session ID.\n    """
    if not is_valid_ssn(ssn):
        raise ValueError("Invalid SSN format")
    
    # Generate cryptographically secure session ID
    session_id = secrets.token_urlsafe(32)
    sessions[session_id] = SessionData(username, email, ssn)
    return session_id

def main():
    """Main entry point with test cases"""
    # Create 5 test sessions
    test_sessions = []
    
    session1 = create_session("john_doe", "john@example.com", "123-45-6789")
    test_sessions.append(session1)
    
    session2 = create_session("jane_smith", "jane@example.com", "987-65-4321")
    test_sessions.append(session2)
    
    session3 = create_session("bob_jones", "bob@example.com", "555-12-3456")
    test_sessions.append(session3)
    
    session4 = create_session("alice_williams", "alice@example.com", "111-22-3333")
    test_sessions.append(session4)
    
    session5 = create_session("charlie_brown", "charlie@example.com", "999-88-7777")
    test_sessions.append(session5)
    
    print("Test session IDs created:")
    for i, sid in enumerate(test_sessions, 1):
        print(f"Session {i}: {sid}")
    
    # Start HTTP server
    server = HTTPServer(('localhost', 8000), InfoHandler)
    print("\\nServer started on http://localhost:8000")
    print("Access /info endpoint with Cookie header: sessionId=<session_id>")
    print("Press Ctrl+C to stop")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\\nShutting down server...")
        server.shutdown()

if __name__ == "__main__":
    main()
