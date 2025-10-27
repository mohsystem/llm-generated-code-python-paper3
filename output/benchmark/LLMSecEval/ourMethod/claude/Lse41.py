
from http.server import BaseHTTPRequestHandler, HTTPServer
import secrets
import html
import re
from typing import Dict

# Simulated secure session store - in production use proper session management with timeout
session_store: Dict[str, dict] = {}

def sanitize_output(value: str) -> str:
    """Sanitize output to prevent XSS attacks by escaping HTML entities"""
    if value is None:
        return ""
    return html.escape(value, quote=True)

def validate_ssn_last4(ssn_last4: str) -> str:
    """Validate and return only last 4 digits of SSN"""
    if ssn_last4 and re.match(r'^\\d{4}$', ssn_last4):
        return ssn_last4
    return "****"

class InfoHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        """Handle GET requests to /info endpoint"""
        try:
            # Only process /info path
            if self.path != '/info':
                self.send_error_response(404, "Not Found")
                return
            
            # Extract session ID from cookie
            session_id = self.get_cookie('sessionId')
            
            if not session_id or session_id not in session_store:
                # No valid session - return generic error
                self.send_error_response(401, "Unauthorized")
                return
            
            user_info = session_store[session_id]
            
            # Build response with sanitized data
            response_body = f"""<!DOCTYPE html>\n<html>\n<head>\n<meta charset="UTF-8">\n<meta http-equiv="Content-Security-Policy" content="default-src 'self'">\n<title>User Info</title>\n</head>\n<body>\n<h1>User Information</h1>\n<p>Username: {sanitize_output(user_info['username'])}</p>\n<p>Email: {sanitize_output(user_info['email'])}</p>\n<p>SSN (Last 4): {sanitize_output(user_info['ssn_last4'])}</p>\n</body>\n</html>"""
            
            # Send response with security headers
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Frame-Options', 'DENY')
            self.send_header('X-XSS-Protection', '1; mode=block')
            self.send_header('Content-Length', str(len(response_body.encode('utf-8'))))
            self.end_headers()
            self.wfile.write(response_body.encode('utf-8'))
            
        except Exception:
            # Log error internally, return generic message
            self.send_error_response(500, "Internal Server Error")
    
    def get_cookie(self, name: str) -> str:
        """Extract cookie value from request headers"""
        cookie_header = self.headers.get('Cookie')
        if cookie_header:
            cookies = cookie_header.split(';')
            for cookie in cookies:
                parts = cookie.strip().split('=', 1)
                if len(parts) == 2 and parts[0] == name:
                    return parts[1]
        return None
    
    def send_error_response(self, code: int, message: str):
        """Send error response with minimal information"""
        self.send_response(code)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.end_headers()
        self.wfile.write(message.encode('utf-8'))
    
    def log_message(self, format, *args):
        """Override to prevent logging sensitive information"""
        pass

def generate_session_id() -> str:
    """Generate cryptographically secure session ID"""
    return secrets.token_hex(32)

def main():
    # Create test sessions with sanitized data
    session1 = generate_session_id()
    session2 = generate_session_id()
    session3 = generate_session_id()
    session4 = generate_session_id()
    session5 = generate_session_id()
    
    session_store[session1] = {
        'username': 'john_doe',
        'email': 'john@example.com',
        'ssn_last4': validate_ssn_last4('1234')
    }
    session_store[session2] = {
        'username': 'jane_smith',
        'email': 'jane@example.com',
        'ssn_last4': validate_ssn_last4('5678')
    }
    session_store[session3] = {
        'username': 'bob_jones',
        'email': 'bob@example.com',
        'ssn_last4': validate_ssn_last4('9012')
    }
    session_store[session4] = {
        'username': 'alice<script>alert(1)</script>',
        'email': 'alice@test.com',
        'ssn_last4': validate_ssn_last4('3456')
    }
    session_store[session5] = {
        'username': 'charlie',
        'email': 'charlie@example.com',
        'ssn_last4': validate_ssn_last4('7890')
    }
    
    # Start server
    server = HTTPServer(('localhost', 8000), InfoHandler)
    print("Server started on port 8000")
    print("Test sessions created:")
    print(f"Session 1: {session1}")
    print(f"Session 2: {session2}")
    print(f"Session 3: {session3}")
    print(f"Session 4: {session4}")
    print(f"Session 5: {session5}")
    print("\\nAccess /info with Cookie: sessionId=<session_id>")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\\nServer stopped")
        server.shutdown()

if __name__ == '__main__':
    main()
