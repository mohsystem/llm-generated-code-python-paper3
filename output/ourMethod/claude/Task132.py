
import os
import secrets
from pathlib import Path
from typing import List, Optional
from datetime import datetime
from threading import Lock
from collections import deque
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import tempfile

MAGIC = b"ENC1"
VERSION = 1
SALT_LENGTH = 16
IV_LENGTH = 12
TAG_LENGTH = 16
PBKDF2_ITERATIONS = 210000
LOG_DIR = "security_logs"


class Task132:
    def __init__(self, log_directory: str):
        if not log_directory or not log_directory.strip():
            raise ValueError("Log directory cannot be null or empty")
        
        self.log_queue: deque = deque()
        self.lock = Lock()
        self.base_log_dir = Path(log_directory).resolve()
        
        if not self.base_log_dir.exists():
            self.base_log_dir.mkdir(parents=True, exist_ok=True)
        
        if not self.base_log_dir.is_dir():
            raise ValueError("Log path must be a directory")
    
    def log_security_event(self, event_type: str, event_details: str) -> None:
        if not event_type or not event_type.strip():
            raise ValueError("Event type cannot be null or empty")
        
        if event_details is None:
            event_details = ""
        
        timestamp = datetime.utcnow().isoformat() + "Z"
        log_entry = f"[{timestamp}] {self._sanitize_input(event_type)}: {self._sanitize_input(event_details)}"
        
        with self.lock:
            self.log_queue.append(log_entry)
    
    def _sanitize_input(self, input_str: str) -> str:
        if input_str is None:
            return ""
        return input_str.replace("\\r", " ").replace("\\n", " ").strip()
    
    def flush_logs_to_file(self, filename: str, passphrase: str) -> None:
        if not filename or not filename.strip():
            raise ValueError("Filename cannot be null or empty")
        
        if not passphrase or len(passphrase) < 12:
            raise ValueError("Passphrase must be at least 12 characters")
        
        target_path = (self.base_log_dir / filename).resolve()
        
        if not str(target_path).startswith(str(self.base_log_dir)):
            raise SecurityError("Path traversal attempt detected")
        
        if target_path.is_symlink():
            raise SecurityError("Symlinks are not allowed")
        
        logs: List[str] = []
        with self.lock:
            while self.log_queue:
                entry = self.log_queue.popleft()
                if entry:
                    logs.append(entry)
        
        if not logs:
            return
        
        plaintext = "\\n".join(logs)
        encrypted_data = self._encrypt_data(plaintext.encode('utf-8'), passphrase)
        
        fd, temp_path = tempfile.mkstemp(dir=self.base_log_dir, suffix='.enc')
        try:
            os.write(fd, encrypted_data)
            os.close(fd)
            os.replace(temp_path, target_path)
        except Exception as e:
            try:
                os.unlink(temp_path)
            except:
                pass
            raise e
    
    def _encrypt_data(self, plaintext: bytes, passphrase: str) -> bytes:
        salt = secrets.token_bytes(SALT_LENGTH)
        iv = secrets.token_bytes(IV_LENGTH)
        
        key = self._derive_key(passphrase, salt)
        
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(iv, plaintext, None)
        
        return MAGIC + bytes([VERSION]) + salt + iv + ciphertext
    
    def read_encrypted_logs(self, filename: str, passphrase: str) -> str:
        if not filename or not filename.strip():
            raise ValueError("Filename cannot be null or empty")
        
        if not passphrase or len(passphrase) < 12:
            raise ValueError("Passphrase must be at least 12 characters")
        
        target_path = (self.base_log_dir / filename).resolve()
        
        if not str(target_path).startswith(str(self.base_log_dir)):
            raise SecurityError("Path traversal attempt detected")
        
        if not target_path.exists() or not target_path.is_file():
            raise FileNotFoundError("File not found or is not a regular file")
        
        encrypted_data = target_path.read_bytes()
        plaintext = self._decrypt_data(encrypted_data, passphrase)
        
        return plaintext.decode('utf-8')
    
    def _decrypt_data(self, encrypted_data: bytes, passphrase: str) -> bytes:
        min_length = len(MAGIC) + 1 + SALT_LENGTH + IV_LENGTH + TAG_LENGTH
        if len(encrypted_data) < min_length:
            raise ValueError("Invalid encrypted data format")
        
        offset = 0
        magic = encrypted_data[offset:offset + len(MAGIC)]
        offset += len(MAGIC)
        
        if magic != MAGIC:
            raise ValueError("Invalid file format")
        
        version = encrypted_data[offset]
        offset += 1
        
        if version != VERSION:
            raise ValueError("Unsupported version")
        
        salt = encrypted_data[offset:offset + SALT_LENGTH]
        offset += SALT_LENGTH
        
        iv = encrypted_data[offset:offset + IV_LENGTH]
        offset += IV_LENGTH
        
        ciphertext = encrypted_data[offset:]
        
        key = self._derive_key(passphrase, salt)
        
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(iv, ciphertext, None)
    
    def _derive_key(self, passphrase: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=PBKDF2_ITERATIONS
        )
        return kdf.derive(passphrase.encode('utf-8'))


class SecurityError(Exception):
    pass


def main():
    try:
        security_logger = Task132(LOG_DIR)
        test_passphrase = "SecurePassword123!@#"
        
        print("Test 1: Basic security event logging")
        security_logger.log_security_event("LOGIN_SUCCESS", "User admin logged in from 192.168.1.100")
        security_logger.log_security_event("LOGIN_FAILURE", "Failed login attempt for user guest")
        security_logger.flush_logs_to_file("test1.enc", test_passphrase)
        logs1 = security_logger.read_encrypted_logs("test1.enc", test_passphrase)
        print(f"Retrieved logs:\\n{logs1}\\n")
        
        print("Test 2: Multiple security events")
        security_logger.log_security_event("FILE_ACCESS", "User accessed sensitive file: /etc/passwd")
        security_logger.log_security_event("PERMISSION_CHANGE", "Permissions changed on /var/log")
        security_logger.log_security_event("FIREWALL_BLOCK", "Blocked connection from 10.0.0.50")
        security_logger.flush_logs_to_file("test2.enc", test_passphrase)
        logs2 = security_logger.read_encrypted_logs("test2.enc", test_passphrase)
        print(f"Retrieved logs:\\n{logs2}\\n")
        
        print("Test 3: Special characters in event details")
        security_logger.log_security_event("SQL_INJECTION_ATTEMPT", "Detected SQL injection: ' OR '1'='1")
        security_logger.log_security_event("XSS_ATTEMPT", "Detected XSS: <script>alert('test')</script>")
        security_logger.flush_logs_to_file("test3.enc", test_passphrase)
        logs3 = security_logger.read_encrypted_logs("test3.enc", test_passphrase)
        print(f"Retrieved logs:\\n{logs3}\\n")
        
        print("Test 4: Input validation")
        try:
            security_logger.log_security_event("", "Empty event type should fail")
        except ValueError as e:
            print(f"Correctly rejected empty event type: {e}\\n")
        
        print("Test 5: Path traversal protection")
        try:
            security_logger.flush_logs_to_file("../../../etc/passwd", test_passphrase)
        except SecurityError as e:
            print(f"Correctly blocked path traversal: {e}")
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
