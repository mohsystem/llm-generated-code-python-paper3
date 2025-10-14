
import sqlite3
import re
import secrets
import hashlib
import base64
from typing import Tuple
from pathlib import Path

DB_PATH = "users.db"
EMAIL_PATTERN = re.compile(r"^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$")
MIN_PASSWORD_LENGTH = 8
MAX_INPUT_LENGTH = 255
SALT_LENGTH = 16
PBKDF2_ITERATIONS = 210000


def initialize_database() -> None:
    """Initialize the database with users table."""
    conn = sqlite3.connect(DB_PATH)
    try:
        cursor = conn.cursor()
        cursor.execute("""\n            CREATE TABLE IF NOT EXISTS users (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                name TEXT NOT NULL,\n                email TEXT UNIQUE NOT NULL,\n                password_hash TEXT NOT NULL,\n                salt TEXT NOT NULL\n            )\n        """)
        conn.commit()
    finally:
        conn.close()


def validate_name(name: str) -> bool:
    """Validate user name."""
    if not name or not name.strip():
        return False
    if len(name) > MAX_INPUT_LENGTH:
        return False
    return bool(re.match(r"^[a-zA-Z\\s'-]{1,255}$", name))


def validate_email(email: str) -> bool:
    """Validate email format."""
    if not email or not email.strip():
        return False
    if len(email) > MAX_INPUT_LENGTH:
        return False
    return bool(EMAIL_PATTERN.match(email))


def validate_password(password: str) -> bool:
    """Validate password strength."""
    if not password or len(password) < MIN_PASSWORD_LENGTH:
        return False
    if len(password) > MAX_INPUT_LENGTH:
        return False
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    return has_upper and has_lower and has_digit and has_special


def generate_salt() -> bytes:
    """Generate a cryptographically secure salt."""
    return secrets.token_bytes(SALT_LENGTH)


def hash_password(password: str, salt: bytes) -> str:
    """Hash password using PBKDF2-HMAC-SHA256."""
    password_bytes = password.encode('utf-8')
    hash_bytes = hashlib.pbkdf2_hmac(
        'sha256',
        password_bytes,
        salt,
        PBKDF2_ITERATIONS,
        dklen=32
    )
    return base64.b64encode(hash_bytes).decode('utf-8')


def register_user(name: str, email: str, password: str) -> Tuple[bool, str]:
    """Register a new user with validated inputs."""
    if not validate_name(name):
        return False, "Invalid name format"
    
    if not validate_email(email):
        return False, "Invalid email format"
    
    if not validate_password(password):
        return False, "Password must be at least 8 characters with uppercase, lowercase, digit, and special character"
    
    try:
        salt = generate_salt()
        password_hash = hash_password(password, salt)
        salt_base64 = base64.b64encode(salt).decode('utf-8')
        
        conn = sqlite3.connect(DB_PATH)
        try:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (name, email, password_hash, salt) VALUES (?, ?, ?, ?)",
                (name, email, password_hash, salt_base64)
            )
            conn.commit()
            return True, "User registered successfully"
        finally:
            conn.close()
            
    except sqlite3.IntegrityError:
        return False, "Email already registered"
    except Exception:
        return False, "Registration failed"


def main() -> None:
    """Test the registration system with 5 test cases."""
    initialize_database()
    
    success1, msg1 = register_user("John Doe", "john@example.com", "SecurePass123!")
    print(f"Test 1: {msg1}")
    
    success2, msg2 = register_user("Jane Smith", "jane@example.com", "ValidP@ss456")
    print(f"Test 2: {msg2}")
    
    success3, msg3 = register_user("", "empty@example.com", "TestPass789!")
    print(f"Test 3: {msg3}")
    
    success4, msg4 = register_user("Bob Wilson", "invalid-email", "TestPass789!")
    print(f"Test 4: {msg4}")
    
    success5, msg5 = register_user("Alice Brown", "alice@example.com", "weak")
    print(f"Test 5: {msg5}")


if __name__ == "__main__":
    main()
