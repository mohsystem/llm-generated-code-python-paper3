
import hashlib
import secrets
import base64
import os
import re
import hmac
from typing import Optional

# Secure configuration from environment variables
DB_CONFIG = {
    'host': os.getenv('DB_HOST'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
    'database': os.getenv('DB_NAME'),
    'ssl': {'ssl_mode': 'VERIFY_IDENTITY'}
}

def generate_salt() -> bytes:
    """Generate cryptographically secure random salt using secrets module"""
    return secrets.token_bytes(16)

def hash_password(password: str, salt: bytes) -> str:
    """\n    Hash password using PBKDF2-HMAC-SHA256 with 210000 iterations\n    Meets security requirements for password hashing\n    """
    # Use PBKDF2 with SHA-256 and high iteration count
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        210000,  # Minimum 210000 iterations as per security requirements
        dklen=32
    )
    return base64.b64encode(key).decode('utf-8')

def validate_input(username: str, password: str) -> bool:
    """\n    Validate input to prevent injection attacks and ensure proper format\n    Returns False if input is invalid\n    """
    # Check for null or empty values
    if not username or not password:
        return False
    
    # Length validation
    if len(username) > 255 or len(password) > 1024:
        return False
    
    # Username must be alphanumeric with underscores only
    if not re.match(r'^[a-zA-Z0-9_]{3,255}$', username):
        return False
    
    return True

def login(username: str, password: str) -> str:
    """\n    Secure login function with parameterized queries and proper error handling\n    Returns redirect URL based on authentication result\n    """
    # Input validation to prevent injection attacks
    if not validate_input(username, password):
        return "redirect:/login?error=invalid"
    
    try:
        # Import here to handle missing library gracefully
        import mysql.connector
        from mysql.connector import Error
        
        # Establish secure database connection with TLS
        connection = mysql.connector.connect(**DB_CONFIG)
        
        if connection.is_connected():
            cursor = connection.cursor(dictionary=True)
            
            # Parameterized query to prevent SQL injection
            query = """\n                SELECT password_hash, salt \n                FROM users \n                WHERE username = %s AND account_locked = FALSE\n                LIMIT 1\n            """
            cursor.execute(query, (username,))
            result = cursor.fetchone()
            
            if result:
                stored_hash = result['password_hash']
                salt = base64.b64decode(result['salt'])
                
                # Hash provided password with stored salt
                computed_hash = hash_password(password, salt)
                
                # Constant-time comparison to prevent timing attacks
                if hmac.compare_digest(computed_hash, stored_hash):
                    cursor.close()
                    connection.close()
                    return "redirect:/dashboard"
                else:
                    # Generic error message to prevent user enumeration
                    cursor.close()
                    connection.close()
                    return "redirect:/login?error=invalid"
            else:
                # Generic error message to prevent user enumeration
                cursor.close()
                connection.close()
                return "redirect:/login?error=invalid"
                
    except Exception as e:
        # Log error without exposing sensitive information
        print("Authentication error occurred", file=__import__('sys').stderr)
        return "redirect:/login?error=system"
    finally:
        # Ensure connection is closed
        if 'connection' in locals() and connection.is_connected():
            connection.close()

def main():
    """Test cases for login function"""
    # Test case 1: Valid login
    print("Test 1:", login("validuser", "ValidPass123!"))
    
    # Test case 2: Invalid password
    print("Test 2:", login("validuser", "wrongpassword"))
    
    # Test case 3: Non-existent user
    print("Test 3:", login("nonexistent", "password"))
    
    # Test case 4: SQL injection attempt (blocked by validation)
    print("Test 4:", login("admin' OR '1'='1", "password"))
    
    # Test case 5: Empty credentials
    print("Test 5:", login("", ""))

if __name__ == "__main__":
    main()
