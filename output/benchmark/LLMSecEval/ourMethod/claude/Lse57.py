
import os
import secrets
import hashlib
import hmac
from typing import Optional, Dict

# Simulated user database for demonstration
user_database: Dict[str, Dict[str, any]] = {}

def generate_salt() -> bytes:
    """Generate cryptographically secure salt - Rule#8, Rule#9"""
    return secrets.token_bytes(16)

def hash_password(password: str, salt: bytes) -> str:
    """Hash password with PBKDF2-HMAC-SHA256 - Rule#6, Rule#15"""
    # Use PBKDF2 with at least 210000 iterations
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 210000, dklen=32)
    return dk.hex()

def constant_time_equals(a: str, b: str) -> bool:
    """Constant-time comparison to prevent timing attacks - Rule#6"""
    if a is None or b is None:
        return False
    return hmac.compare_digest(a.encode('utf-8'), b.encode('utf-8'))

def is_valid_email(email: str) -> bool:
    """Validate email format - Rule#1, Rule#13"""
    if not email or len(email) > 254:
        return False
    # Basic email validation
    import re
    pattern = r'^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$'
    return bool(re.match(pattern, email))

def meets_password_policy(password: str) -> bool:
    """Verify password meets policy - Rule#15"""
    if not password or len(password) < 12:
        return False
    # Require at least: 12 chars, 1 upper, 1 lower, 1 digit, 1 special
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
    return has_upper and has_lower and has_digit and has_special

def change_email(session_user_id: str, old_email: str, new_email: str, confirm_password: str) -> str:
    """Change email securely - Rule#1, Rule#2, Rule#16"""
    try:
        # Input validation - Rule#13
        if not session_user_id or not session_user_id.strip():
            return "Error: Not authenticated"

        if (
                not old_email or not old_email.strip()
                or not new_email or not new_email.strip()
                or not confirm_password
        ):
            return "Error: All fields required"

        # ... (rest of function)
    except Exception:
        # ... (error handling)
        raise

        
        # Sanitize inputs - trim whitespace only
        old_email = old_email.strip()
        new_email = new_email.strip()
        
        # Validate email formats - Rule#13
        if not is_valid_email(old_email) or not is_valid_email(new_email):
            return "Error: Invalid email format"
        
        # Check email length limits - Rule#14
        if len(old_email) > 254 or len(new_email) > 254:
            return "Error: Email too long"
        
        # Prevent same old and new email
        if old_email.lower() == new_email.lower():
            return "Error: New email must be different"
        
        # Retrieve user record
        user = user_database.get(session_user_id)
        if not user:
            return "Error: User not found"
        
        # Verify old email matches current email - Rule#1
        if not constant_time_equals(user['email'], old_email):
            return "Error: Old email incorrect"
        
        # Verify password - Rule#6, Rule#15
        provided_hash = hash_password(confirm_password, user['salt'])
        if not constant_time_equals(user['password_hash'], provided_hash):
            # Clear sensitive data
            del provided_hash
            return "Error: Password incorrect"
        
        # Clear password hash from memory
        del provided_hash
        
        # Check if new email already exists
        for uid, record in user_database.items():
            if constant_time_equals(record['email'], new_email):
                return "Error: Email already in use"
        
        # Update email
        user['email'] = new_email
        
        return "Success: Email changed"
        
    except Exception as e:
        # Rule#1, Rule#16 - Generic error, log details securely
        print(f"Email change error: {type(e).__name__}", file=__import__('sys').stderr)
        return "Error: Operation failed"

def create_user(user_id: str, email: str, password: str) -> None:
    """Helper to create test user"""
    salt = generate_salt()
    password_hash = hash_password(password, salt)
    user_database[user_id] = {
        'email': email,
        'password_hash': password_hash,
        'salt': salt
    }

if __name__ == "__main__":
    # Test cases
    print("=== Email Change System Test Cases ===\\n")
    
    # Setup test users
    create_user("user1", "alice@example.com", "SecurePass123!")
    create_user("user2", "bob@example.com", "AnotherPass456#")
    
    # Test 1: Successful email change
    print("Test 1: Valid email change")
    result1 = change_email("user1", "alice@example.com", "alice.new@example.com", "SecurePass123!")
    print(result1)
    print()
    
    # Test 2: Wrong old email
    print("Test 2: Wrong old email")
    result2 = change_email("user2", "wrong@example.com", "bob.new@example.com", "AnotherPass456#")
    print(result2)
    print()
    
    # Test 3: Wrong password
    print("Test 3: Wrong password")
    result3 = change_email("user2", "bob@example.com", "bob.new@example.com", "WrongPassword!")
    print(result3)
    print()
    
    # Test 4: Invalid email format
    print("Test 4: Invalid email format")
    result4 = change_email("user1", "alice.new@example.com", "invalid-email", "SecurePass123!")
    print(result4)
    print()
    
    # Test 5: Empty fields
    print("Test 5: Empty fields")
    result5 = change_email("user2", "", "bob.final@example.com", "AnotherPass456#")
    print(result5)
    print()
