
from flask import Flask, session, redirect, url_for
import secrets
import re

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Secure secret key

class Lse42:
    # Simulated session store
    session_store = {}
    
    @staticmethod
    def sanitize(input_str):
        """Sanitize input to prevent XSS"""
        if not input_str:
            return ""
        # Remove potentially dangerous characters and scripts
        sanitized = re.sub(r'[<>"\'&]', '', str(input_str))
        sanitized = re.sub(r'javascript:', '', sanitized, flags=re.IGNORECASE)
        sanitized = re.sub(r'on\\w+\\s*=', '', sanitized, flags=re.IGNORECASE)
        return sanitized
    
    @staticmethod
    def mask_ssn(ssn):
        """Mask SSN for security (show only last 4 digits)"""
        if not ssn or len(ssn) < 4:
            return "***"
        return f"XXX-XX-{ssn[-4:]}"
    
    @staticmethod
    def create_session(session_id, username, email, ssn):
        """Create a session with user data"""
        Lse42.session_store[session_id] = {
            'username': Lse42.sanitize(username),
            'email': Lse42.sanitize(email),
            'ssn': Lse42.mask_ssn(ssn),
            'authenticated': True
        }
        return session_id
    
    @staticmethod
    def info(session_id):
        """Route handler for /info"""
        if not session_id or session_id not in Lse42.session_store:
            return "Error: Invalid or expired session. Please log in."
        
        session_data = Lse42.session_store.get(session_id)
        
        if not session_data.get('authenticated'):
            return "Error: Unauthorized access."
        
        username = session_data.get('username', 'N/A')
        email = session_data.get('email', 'N/A')
        ssn = session_data.get('ssn', 'N/A')
        
        return f"User Information:\\nUsername: {username}\\nEmail: {email}\\nSSN: {ssn}"


@app.route('/info', methods=['GET'])
def info_route():
    """Flask route for /info"""
    session_id = session.get('session_id')
    return Lse42.info(session_id)


def main():
    """Test cases"""
    print("Testing /info route with session management\\n")
    
    # Test case 1: Valid session
    session1 = Lse42.create_session("sess001", "john_doe", "john@example.com", "123456789")
    print("Test 1 - Valid session:")
    print(Lse42.info("sess001"))
    print()
    
    # Test case 2: Another valid session
    session2 = Lse42.create_session("sess002", "jane_smith", "jane@example.com", "987654321")
    print("Test 2 - Another valid session:")
    print(Lse42.info("sess002"))
    print()
    
    # Test case 3: Invalid session ID
    print("Test 3 - Invalid session:")
    print(Lse42.info("invalid_session"))
    print()
    
    # Test case 4: None session ID
    print("Test 4 - None session:")
    print(Lse42.info(None))
    print()
    
    # Test case 5: XSS attempt in username
    session3 = Lse42.create_session("sess003", "<script>alert('xss')</script>user", 
                                    "test@example.com", "555667777")
    print("Test 5 - XSS attempt (sanitized):")
    print(Lse42.info("sess003"))


if __name__ == "__main__":
    main()
