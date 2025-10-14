
import socket
import secrets
import hashlib
import base64
import os
import re
from pathlib import Path
from typing import Optional, Tuple
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

PORT = 8443
USERS_FILE = "users.dat"
PBKDF2_ITERATIONS = 210000
SALT_LENGTH = 16
MAX_USERNAME_LENGTH = 64
MAX_PASSWORD_LENGTH = 128
MAX_MESSAGE_LENGTH = 4096


class SecurePassword:
    def __init__(self, salt: bytes, hash_value: bytes):
        self.salt = bytes(salt)
        self.hash = bytes(hash_value)


class ChatServer:
    def __init__(self, users_file: str):
        self.users = {}
        base_dir = Path.cwd().resolve()
        self.users_file_path = (Path(users_file).resolve())
        
        if not str(self.users_file_path).startswith(str(base_dir)):
            raise ValueError("Users file path outside allowed directory")
        
        self._load_users()
    
    def _load_users(self) -> None:
        if not self.users_file_path.exists():
            return
        
        if not self.users_file_path.is_file():
            raise ValueError("Users file is not a regular file")
        
        try:
            with open(self.users_file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or len(line) > MAX_MESSAGE_LENGTH:
                        continue
                    parts = line.split(':', 2)
                    if len(parts) == 3:
                        username = self._validate_username(parts[0])
                        salt = base64.b64decode(parts[1])
                        hash_value = base64.b64decode(parts[2])
                        if len(salt) == SALT_LENGTH and len(hash_value) == 32:
                            self.users[username] = SecurePassword(salt, hash_value)
        except Exception:
            pass
    
    def _save_users(self) -> None:
        temp_file = self.users_file_path.with_suffix('.tmp')
        try:
            with open(temp_file, 'w', encoding='utf-8') as f:
                for username, sec_pass in self.users.items():
                    salt_b64 = base64.b64encode(sec_pass.salt).decode('ascii')
                    hash_b64 = base64.b64encode(sec_pass.hash).decode('ascii')
                    f.write(f"{username}:{salt_b64}:{hash_b64}\\n")
                f.flush()
                os.fsync(f.fileno())
            temp_file.replace(self.users_file_path)
        except Exception as e:
            if temp_file.exists():
                temp_file.unlink()
            raise e
    
    def _validate_username(self, username: str) -> str:
        if not username or len(username) > MAX_USERNAME_LENGTH:
            raise ValueError("Invalid username length")
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            raise ValueError("Invalid username format")
        return username
    
    def _validate_password(self, password: str) -> str:
        if not password or len(password) > MAX_PASSWORD_LENGTH:
            raise ValueError("Invalid password length")
        if len(password) < 8:
            raise ValueError("Password too short")
        return password
    
    def _hash_password(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))
    
    def _verify_password(self, password: str, sec_pass: SecurePassword) -> bool:
        hash_value = self._hash_password(password, sec_pass.salt)
        return secrets.compare_digest(hash_value, sec_pass.hash)
    
    def register_user(self, username: str, password: str) -> str:
        username = self._validate_username(username)
        password = self._validate_password(password)
        
        if username in self.users:
            return "ERROR:User already exists"
        
        salt = secrets.token_bytes(SALT_LENGTH)
        hash_value = self._hash_password(password, salt)
        
        self.users[username] = SecurePassword(salt, hash_value)
        self._save_users()
        
        return "SUCCESS:User registered"
    
    def authenticate_user(self, username: str, password: str) -> str:
        username = self._validate_username(username)
        password = self._validate_password(password)
        
        sec_pass = self.users.get(username)
        if sec_pass is None:
            return "ERROR:Authentication failed"
        
        if self._verify_password(password, sec_pass):
            return "SUCCESS:Authenticated"
        else:
            return "ERROR:Authentication failed"
    
    def process_request(self, request: str) -> str:
        if not request or len(request) > MAX_MESSAGE_LENGTH:
            return "ERROR:Invalid request"
        
        try:
            parts = request.split(':', 2)
            if len(parts) < 3:
                return "ERROR:Invalid request format"
            
            command = parts[0]
            username = parts[1]
            password = parts[2]
            
            if command == "REGISTER":
                return self.register_user(username, password)
            elif command == "LOGIN":
                return self.authenticate_user(username, password)
            else:
                return "ERROR:Unknown command"
        except ValueError:
            return "ERROR:Invalid input"
        except Exception:
            return "ERROR:Server error"


class ChatClient:
    def __init__(self, server_host: str, server_port: int):
        self.server_host = server_host
        self.server_port = server_port
    
    def send_request(self, request: str) -> str:
        if not request or len(request) > MAX_MESSAGE_LENGTH:
            raise ValueError("Invalid request")
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(5.0)
            sock.connect((self.server_host, self.server_port))
            sock.sendall((request + '\\n').encode('utf-8'))
            response = sock.recv(MAX_MESSAGE_LENGTH).decode('utf-8').strip()
            
            if not response or len(response) > MAX_MESSAGE_LENGTH:
                raise ValueError("Invalid response")
            
            return response


def main():
    print("Test Case 1: Register user")
    server1 = ChatServer("test_users1.dat")
    result1 = server1.process_request("REGISTER:alice:SecurePass123!")
    print(result1)
    
    print("\\nTest Case 2: Login with correct credentials")
    result2 = server1.process_request("LOGIN:alice:SecurePass123!")
    print(result2)
    
    print("\\nTest Case 3: Login with incorrect password")
    result3 = server1.process_request("LOGIN:alice:WrongPassword")
    print(result3)
    
    print("\\nTest Case 4: Register duplicate user")
    result4 = server1.process_request("REGISTER:alice:AnotherPass456!")
    print(result4)
    
    print("\\nTest Case 5: Invalid command")
    result5 = server1.process_request("INVALID:bob:password123")
    print(result5)
    
    if Path("test_users1.dat").exists():
        Path("test_users1.dat").unlink()


if __name__ == "__main__":
    main()
