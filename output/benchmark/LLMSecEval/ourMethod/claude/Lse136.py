
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import hashlib
import secrets
import hmac
from typing import Dict, Tuple, Optional

# Simulated secure credential store
# In production, use environment variables or secure vault
user_store: Dict[str, bytes] = {}
salt_store: Dict[str, bytes] = {}

def store_user(username: str, password: str) -> None:
    """Store user with securely hashed password and unique salt"""
    # Generate cryptographically secure unique salt per user
    salt = secrets.token_bytes(16)
    
    # Hash password with PBKDF2-HMAC-SHA-256 and high iteration count
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 210000)
    
    user_store[username] = hashed
    salt_store[username] = salt

# Initialize test users with secure passwords
# Password requirements: minimum 8 characters
store_user("admin", "SecurePass123!")
store_user("user1", "MyPassword456!")
store_user("testuser", "TestPass789!")
store_user("moderator", "ModPass321!")
store_user("developer", "DevPass654!")

def is_valid_input(input_str: Optional[str]) -> bool:
    """Validate input to prevent injection attacks"""
    if input_str is None or len(input_str) == 0:
        return False
    # Check length constraints
    if len(input_str) > 100:
        return False
    # Allow only safe characters
    import re
    return bool(re.match(r'^[a-zA-Z0-9!@#$%^&*()_+\-=\\[\\]{};\':"\\\\|,.<>/?]+$', input_str))

def check_credentials(username: str, password: str) -> bool:
    """Check credentials securely with constant-time comparison"""
    # Validate inputs before processing
    if not is_valid_input(username) or not is_valid_input(password):
        return False
    
    # Check if user exists
    if username not in user_store or username not in salt_store:
        # Perform dummy computation to prevent timing attacks
        dummy_salt = secrets.token_bytes(16)
        hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), dummy_salt, 210000)
        return False
    
    try:
        # Retrieve stored salt and hash
        salt = salt_store[username]
        stored_hash = user_store[username]
        
        # Hash provided password with stored salt
        provided_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 210000)
        
        # Use constant-time comparison to prevent timing attacks
        return hmac.compare_digest(stored_hash, provided_hash)
    except Exception:
        return False

class CheckModHandler(BaseHTTPRequestHandler):
    """HTTP handler for /check_mod endpoint"""
    
    def do_GET(self) -> None:
        """Handle GET requests"""
        try:
            # Parse URL
            parsed_url = urlparse(self.path)
            
            # Check if path is /check_mod
            if parsed_url.path != '/check_mod':
                self.send_error_response(404)
                return
            
            # Parse query parameters safely
            query_params = parse_qs(parsed_url.query)
            
            # Extract username and password
            username_list = query_params.get('username', [])
            password_list = query_params.get('password', [])
            
            if not username_list or not password_list:
                self.send_response_message("false", 400)
                return
            
            username = username_list[0]
            password = password_list[0]
            
            # Check credentials
            if check_credentials(username, password):
                self.send_response_message("true", 200)
            else:
                self.send_response_message("false", 401)
                
        except Exception:
            # Generic error message to prevent information disclosure
            self.send_response_message("false", 500)
    
    def send_response_message(self, message: str, status_code: int) -> None:
        """Send response with proper headers"""
        self.send_response(status_code)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.end_headers()
        self.wfile.write(message.encode('utf-8'))
    
    def send_error_response(self, status_code: int) -> None:
        """Send error response"""
        self.send_response_message("false", status_code)
    
    def log_message(self, format: str, *args) -> None:
        """Override to prevent logging sensitive information"""
        # Only log method and path, not query parameters
        pass

def main() -> None:
    """Start HTTP server"""
    server_address = ('', 8000)
    httpd = HTTPServer(server_address, CheckModHandler)
    
    print("Server started on port 8000")
    print("\\nTest cases:")
    print("1. Valid: http://localhost:8000/check_mod?username=admin&password=SecurePass123!")
    print("2. Valid: http://localhost:8000/check_mod?username=user1&password=MyPassword456!")
    print("3. Invalid password: http://localhost:8000/check_mod?username=admin&password=wrong")
    print("4. Invalid user: http://localhost:8000/check_mod?username=invalid&password=test")
    print("5. Missing params: http://localhost:8000/check_mod?username=admin")
    
    httpd.serve_forever()

if __name__ == '__main__':
    main()
