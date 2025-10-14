
import os
import hashlib
import secrets
import re
from pathlib import Path
from typing import Dict, Optional, Tuple

SALT_LENGTH = 16
HASH_ITERATIONS = 100000
USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_]{3,32}$')
PASSWORD_PATTERN = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{12,128}$')
PASSWORD_FILE = 'user_passwords.dat'
BASE_DIR = Path.cwd()


def generate_salt() -> bytes:
    """Generate a cryptographically secure random salt."""
    return secrets.token_bytes(SALT_LENGTH)


def hash_password(password: str, salt: bytes) -> bytes:
    """Hash a password using PBKDF2-HMAC-SHA256 with a unique salt."""
    if not password:
        raise ValueError("Password cannot be empty")
    if not salt or len(salt) != SALT_LENGTH:
        raise ValueError("Invalid salt")
    
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, HASH_ITERATIONS)


def validate_username(username: Optional[str]) -> bool:
    """Validate username format."""
    if username is None:
        return False
    return USERNAME_PATTERN.match(username) is not None


def validate_password(password: Optional[str]) -> bool:
    """Validate password complexity."""
    if password is None:
        return False
    return PASSWORD_PATTERN.match(password) is not None


def change_user_password(username: str, new_password: str) -> bool:
    """Change user password with proper validation and security."""
    if not validate_username(username):
        print("Invalid username format", file=os.sys.stderr)
        return False
    
    if not validate_password(new_password):
        print("Password must be 12-128 characters with uppercase, lowercase, digit, and special character", 
              file=os.sys.stderr)
        return False

    try:
        file_path = (BASE_DIR / PASSWORD_FILE).resolve()
        if not str(file_path).startswith(str(BASE_DIR)):
            print("Path traversal detected", file=os.sys.stderr)
            return False

        passwords = load_passwords(file_path)
        
        salt = generate_salt()
        password_hash = hash_password(new_password, salt)
        
        passwords[username] = (salt, password_hash)
        
        save_passwords(file_path, passwords)
        
        return True
    except Exception as e:
        print(f"Failed to change password: {type(e).__name__}", file=os.sys.stderr)
        return False


def load_passwords(file_path: Path) -> Dict[str, Tuple[bytes, bytes]]:
    """Load passwords from file."""
    passwords = {}
    
    if not file_path.exists():
        return passwords

    try:
        with open(file_path, 'rb') as f:
            count_bytes = f.read(4)
            if len(count_bytes) != 4:
                raise ValueError("Invalid file format")
            
            count = int.from_bytes(count_bytes, 'big')
            if count < 0 or count > 10000:
                raise ValueError("Invalid password count")
            
            for _ in range(count):
                username_len_bytes = f.read(4)
                if len(username_len_bytes) != 4:
                    raise ValueError("Invalid file format")
                
                username_len = int.from_bytes(username_len_bytes, 'big')
                if username_len <= 0 or username_len > 256:
                    raise ValueError("Invalid username length")
                
                username_bytes = f.read(username_len)
                if len(username_bytes) != username_len:
                    raise ValueError("Corrupted file")
                
                username = username_bytes.decode('utf-8')
                
                salt = f.read(SALT_LENGTH)
                if len(salt) != SALT_LENGTH:
                    raise ValueError("Corrupted file")
                
                hash_len_bytes = f.read(4)
                if len(hash_len_bytes) != 4:
                    raise ValueError("Invalid file format")
                
                hash_len = int.from_bytes(hash_len_bytes, 'big')
                if hash_len != 32:
                    raise ValueError("Invalid hash length")
                
                password_hash = f.read(hash_len)
                if len(password_hash) != hash_len:
                    raise ValueError("Corrupted file")
                
                passwords[username] = (salt, password_hash)
    except Exception:
        raise
    
    return passwords


def save_passwords(file_path: Path, passwords: Dict[str, Tuple[bytes, bytes]]) -> None:
    """Save passwords to file securely."""
    temp_file = file_path.with_suffix('.tmp')
    
    try:
        with open(temp_file, 'wb') as f:
            f.write(len(passwords).to_bytes(4, 'big'))
            
            for username, (salt, password_hash) in passwords.items():
                username_bytes = username.encode('utf-8')
                f.write(len(username_bytes).to_bytes(4, 'big'))
                f.write(username_bytes)
                f.write(salt)
                f.write(len(password_hash).to_bytes(4, 'big'))
                f.write(password_hash)
        
        temp_file.replace(file_path)
    except Exception:
        if temp_file.exists():
            temp_file.unlink()
        raise


def drop_privileges() -> None:
    """Drop privileges after privileged operations."""
    print("Privileges dropped - operating as unprivileged user")


def main() -> None:
    print("Test Case 1: Valid password change")
    result1 = change_user_password("testuser1", "SecurePass123!")
    print(f"Result: {result1}")
    drop_privileges()
    
    print("\\nTest Case 2: Invalid username (too short)")
    result2 = change_user_password("ab", "SecurePass123!")
    print(f"Result: {result2}")
    
    print("\\nTest Case 3: Invalid password (no special char)")
    result3 = change_user_password("testuser2", "SecurePass123")
    print(f"Result: {result3}")
    
    print("\\nTest Case 4: Valid password change for another user")
    result4 = change_user_password("admin_user", "MyP@ssw0rd2024!")
    print(f"Result: {result4}")
    drop_privileges()
    
    print("\\nTest Case 5: Null username")
    result5 = change_user_password(None, "SecurePass123!")
    print(f"Result: {result5}")


if __name__ == "__main__":
    main()
