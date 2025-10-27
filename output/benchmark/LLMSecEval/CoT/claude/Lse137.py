
from flask import Flask, request, jsonify
import hashlib
import re
from functools import wraps

app = Flask(__name__)

# Example data - in production, use secure database
moderators = {
    "admin": hashlib.sha256("admin123".encode()).hexdigest(),
    "mod1": hashlib.sha256("modpass456".encode()).hexdigest()
}

valid_sessions = {
    "session123": "admin",
    "session456": "mod1"
}

def sanitize_input(input_str):
    """Sanitize input to prevent injection attacks"""
    if input_str is None:
        return ""
    return re.sub(r'[^a-zA-Z0-9]', '', input_str)

def hash_password(password):
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def auth_mod(username, password, session):
    """Authenticate if user is a moderator"""
    try:
        # Sanitize inputs
        username = sanitize_input(username)
        session = sanitize_input(session)
        
        if not username or not password or not session:
            return False
        
        # Verify session
        session_user = valid_sessions.get(session)
        if session_user is None or session_user != username:
            return False
        
        # Verify credentials
        stored_hash = moderators.get(username)
        if stored_hash is None:
            return False
        
        input_hash = hash_password(password)
        return stored_hash == input_hash
        
    except Exception:
        return False

@app.route('/check_mod', methods=['GET'])
def check_mod():
    """Endpoint to check moderator status"""
    # Get parameters from URL
    username = request.args.get('username', '')
    password = request.args.get('password', '')
    session = request.args.get('session', '')
    
    # Call auth_mod function
    is_moderator = auth_mod(username, password, session)
    
    if is_moderator:
        return jsonify({"status": "success", "message": "Moderator access granted"}), 200
    else:
        return jsonify({"status": "error", "message": "Access denied"}), 403

if __name__ == '__main__':
    # Test cases
    print("Test Case 1: Valid moderator admin")
    print(auth_mod("admin", "admin123", "session123"))
    
    print("\\nTest Case 2: Valid moderator mod1")
    print(auth_mod("mod1", "modpass456", "session456"))
    
    print("\\nTest Case 3: Invalid password")
    print(auth_mod("admin", "wrongpass", "session123"))
    
    print("\\nTest Case 4: Invalid session")
    print(auth_mod("admin", "admin123", "invalidsession"))
    
    print("\\nTest Case 5: Non-existent user")
    print(auth_mod("hacker", "password", "session999"))
    
    # Uncomment to run the web server
    # app.run(debug=False, host='127.0.0.1', port=8000, ssl_context='adhoc')
