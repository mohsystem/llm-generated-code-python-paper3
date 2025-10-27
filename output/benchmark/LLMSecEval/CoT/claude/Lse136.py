
import hashlib
import secrets
import hmac
from flask import Flask, request

app = Flask(__name__)

# Simulated user database with hashed passwords
user_database = {}
salt_database = {}

def generate_salt():
    """Generate a cryptographically secure salt"""
    return secrets.token_bytes(16)

def hash_password(password, salt):
    """Hash password with salt using SHA-256"""
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

def add_user(username, password):
    """Add user to database with hashed password"""
    salt = generate_salt()
    hashed_password = hash_password(password, salt)
    user_database[username] = hashed_password
    salt_database[username] = salt

# Initialize test users
add_user("admin", "Admin@123")
add_user("user1", "Pass@word1")
add_user("testuser", "Test@123")

def check_mod(username, password):
    """\n    Securely validate username and password\n    Returns 'true' if credentials are valid, 'false' otherwise\n    """
    if not username or not password:
        return "false"
    
    # Sanitize input
    username = username.strip()
    
    if username not in user_database:
        return "false"
    
    try:
        salt = salt_database[username]
        hashed_password = hash_password(password, salt)
        stored_hash = user_database[username]
        
        # Use constant-time comparison to prevent timing attacks
        if hmac.compare_digest(hashed_password, stored_hash):
            return "true"
    except Exception as e:
        print(f"Error during authentication: {e}")
    
    return "false"

@app.route('/check_mod', methods=['POST'])
def check_mod_endpoint():
    """\n    HTTP endpoint for credential validation\n    Only accepts POST requests for security\n    """
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    return check_mod(username, password)

if __name__ == '__main__':
    # Test cases
    print("Test Case 1 (Valid admin):", check_mod("admin", "Admin@123"))
    print("Test Case 2 (Valid user1):", check_mod("user1", "Pass@word1"))
    print("Test Case 3 (Invalid password):", check_mod("admin", "wrongpass"))
    print("Test Case 4 (Non-existent user):", check_mod("hacker", "password"))
    print("Test Case 5 (Empty credentials):", check_mod("", ""))
    
    # Uncomment to run the Flask server
    # app.run(debug=False, host='127.0.0.1', port=5000, ssl_context='adhoc')
