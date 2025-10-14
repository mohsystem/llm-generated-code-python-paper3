
import hashlib
import secrets
import os
from pathlib import Path
from typing import Optional


def constant_time_equals(a: bytes, b: bytes) -> bool:
    if not isinstance(a, bytes) or not isinstance(b, bytes):
        return False
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


def hash_password(password: str, salt: bytes) -> bytes:
    if not password or not salt or len(salt) != 16:
        raise ValueError("Invalid password or salt")
    
    password_bytes = password.encode('utf-8')
    hash_value = hashlib.sha256(salt + password_bytes).digest()
    
    for _ in range(10000):
        hash_value = hashlib.sha256(hash_value).digest()
    
    return hash_value


def verify_password(stored_password_file_path: str, entered_password: str) -> bool:
    if not stored_password_file_path or not entered_password:
        return False
    
    try:
        file_path = Path(stored_password_file_path).resolve()
        base_dir = Path.cwd().resolve()
        
        if not str(file_path).startswith(str(base_dir)):
            return False
        
        if not file_path.exists() or not file_path.is_file():
            return False
        
        with open(file_path, 'r', encoding='utf-8') as f:
            salt_hex = f.readline().strip()
            hash_hex = f.readline().strip()
        
        if not salt_hex or not hash_hex:
            return False
        
        salt = bytes.fromhex(salt_hex)
        stored_hash = bytes.fromhex(hash_hex)
        
        if len(salt) != 16:
            return False
        
        entered_hash = hash_password(entered_password, salt)
        
        return constant_time_equals(stored_hash, entered_hash)
    
    except (OSError, ValueError, Exception):
        return False


def store_password(file_path: str, password: str) -> None:
    if not file_path or not password:
        raise ValueError("Invalid file path or password")
    
    path = Path(file_path).resolve()
    base_dir = Path.cwd().resolve()
    
    if not str(path).startswith(str(base_dir)):
        raise ValueError("Invalid file path")
    
    salt = secrets.token_bytes(16)
    hash_value = hash_password(password, salt)
    
    temp_path = path.with_suffix('.tmp')
    with open(temp_path, 'w', encoding='utf-8') as f:
        f.write(salt.hex() + '\\n')
        f.write(hash_value.hex())
        f.flush()
        os.fsync(f.fileno())
    
    temp_path.replace(path)


def main():
    try:
        store_password("test_password1.txt", "SecurePass123!")
        print("Test 1:", verify_password("test_password1.txt", "SecurePass123!"))
        
        store_password("test_password2.txt", "MyP@ssw0rd")
        print("Test 2:", verify_password("test_password2.txt", "MyP@ssw0rd"))
        
        print("Test 3:", verify_password("test_password2.txt", "WrongPassword"))
        
        store_password("test_password3.txt", "Admin2024#")
        print("Test 4:", verify_password("test_password3.txt", "Admin2024#"))
        
        print("Test 5:", verify_password("test_password1.txt", "WrongPass"))
        
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
