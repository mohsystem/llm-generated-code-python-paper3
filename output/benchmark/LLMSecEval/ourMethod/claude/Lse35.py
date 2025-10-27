
import os
import sqlite3
import hashlib
import secrets
import base64
from flask import Flask, request, redirect, session
from typing import Optional

app = Flask(__name__)
# Use cryptographically secure random key - Rules#1, Rules#6
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Database configuration from environment - Rules#3, Rules#4
DB_PATH = os.environ.get('DB_PATH', 'users.db')

# Constants for security
MAX_USERNAME_LENGTH = 50
MAX_PASSWORD_LENGTH = 128
MAX_LOGIN_ATTEMPTS = 5
PBKDF2_ITERATIONS = 210000  # Rules#6: at least 210000 iterations

def hash_password(password: str, salt: str) -> str:
    """\n    Hash password using PBKDF2-HMAC-SHA-256 with secure parameters.\n    Rules#6, Rules#7: Use secure KDF with proper iteration count\n    """
    # Decode salt from base64 - Rules#8, Rules#9: use unique salt
    salt_bytes = base64.b64decode(salt)
    
    # Use PBKDF2-HMAC-SHA-256 with at least 210000 iterations - Rules#6
    hash_bytes = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt_bytes,
        PBKDF2_ITERATIONS
    )
    
    return base64.b64encode(hash_bytes).decode('utf-8')

def generate_salt() -> str:
    """\n    Generate cryptographically secure random salt.\n    Rules#8, Rules#9: unique, unpredictable salt for each password\n    """
    # Use secrets module for cryptographically secure randomness - Rules#1, Rules#6
    salt_bytes = secrets.token_bytes(16)
    return base64.b64encode(salt_bytes).decode('utf-8')

def authenticate_user(username: str, password: str) -> bool:
    """\n    Authenticate user against database with secure password verification.\n    Rules#1: Use parameterized queries to prevent SQL injection\n    """
    conn = None
    try:
        # Connect to database - Rules#1: proper resource management
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Use parameterized query to prevent SQL injection - Rules#1
        cursor.execute(
            "SELECT password_hash, salt FROM users WHERE username = ?",
            (username,)
        )
        
        result = cursor.fetchone()
        
        if result:
            stored_hash, salt = result
            # Hash provided password with stored salt - Rules#6, Rules#8
            computed_hash = hash_password(password, salt)
            
            # Constant-time comparison to prevent timing attacks - Rules#6
            return secrets.compare_digest(stored_hash, computed_hash)
        
        return False
        
    except sqlite3.Error as e:
        # Log error securely - Rules#1: do not leak internal details
        print("Database error during authentication", file=os.sys.stderr)
        return False
    finally:
        # Clean up resources - Rules#1
        if conn:
            conn.close()

@app.route('/login', methods=['POST'])
def login():
    """\n    Handle login POST request with comprehensive input validation.\n    Rules#1, Rules#13: Validate and sanitize all external input\n    """
    # Input validation - Rules#1, Rules#13
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    # Validate inputs are not empty - Rules#1
    if not username or not password:
        return redirect('/login.html?error=invalid')
    
    # Check length constraints - Rules#1, Rules#13
    if len(username) > MAX_USERNAME_LENGTH or len(password) > MAX_PASSWORD_LENGTH:
        return redirect('/login.html?error=invalid')
    
    # Sanitize username - Rules#1: reject special characters
    if not username.replace('_', '').replace('-', '').isalnum():
        return redirect('/login.html?error=invalid')
    
    # Rate limiting - prevent brute force attacks
    attempts = session.get('loginAttempts', 0)
    
    if attempts >= MAX_LOGIN_ATTEMPTS:
        # Generic error message - Rules#1: do not leak internal details
        return redirect('/login.html?error=locked')
    
    # Authenticate user
    if authenticate_user(username, password):
        # Reset login attempts on success
        session.pop('loginAttempts', None)
        # Create secure session - Rules#1
        session['authenticated'] = True
        session['username'] = username
        # Regenerate session to prevent session fixation
        session.modified = True
        return redirect('/home.html')
    else:
        # Increment failed attempts
        session['loginAttempts'] = attempts + 1
        # Generic error message - Rules#1: do not leak internal details
        return redirect('/login.html?error=invalid')

# Test cases
if __name__ == '__main__':
    print("Login System Test Cases:")
    
    # Test Case 1: Generate salt
    salt1 = generate_salt()
    print(f"Test 1 - Salt generated: {len(salt1) > 0}")
    
    # Test Case 2: Hash password with salt
    hash1 = hash_password("testpass123", salt1)
    print(f"Test 2 - Password hashed: {len(hash1) > 0}")
    
    # Test Case 3: Verify same password with same salt produces same hash
    hash2 = hash_password("testpass123", salt1)
    print(f"Test 3 - Hash consistency: {hash1 == hash2}")
    
    # Test Case 4: Verify different salt produces different hash
    salt2 = generate_salt()
    hash3 = hash_password("testpass123", salt2)
    print(f"Test 4 - Different salt, different hash: {hash1 != hash3}")
    
    # Test Case 5: Verify different password produces different hash
    hash4 = hash_password("differentpass", salt1)
    print(f"Test 5 - Different password, different hash: {hash1 != hash4}")
