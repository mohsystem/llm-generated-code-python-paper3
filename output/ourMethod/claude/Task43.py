
import secrets
import time
import hashlib
import base64
from typing import Dict, Optional, Tuple
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


@dataclass
class SessionData:
    user_id: str
    encrypted_data: bytes
    creation_time: float
    expiration_time: float


class SessionManager:
    GCM_IV_LENGTH: int = 12
    GCM_TAG_LENGTH: int = 16
    SESSION_TIMEOUT_SECONDS: int = 1800
    
    def __init__(self):
        self.encryption_key: bytes = AESGCM.generate_key(bit_length=256)
        self.aesgcm: AESGCM = AESGCM(self.encryption_key)
        self.sessions: Dict[str, SessionData] = {}
    
    def create_session(self, user_id: str, user_data: str) -> str:
        if not user_id or not isinstance(user_id, str) or len(user_id) > 256:
            raise ValueError("Invalid user_id")
        if not isinstance(user_data, str) or len(user_data) > 4096:
            raise ValueError("Invalid user_data")
        
        session_id = self._generate_secure_session_id()
        encrypted_data = self._encrypt_data(user_data)
        
        now = time.time()
        expiration = now + self.SESSION_TIMEOUT_SECONDS
        
        session = SessionData(
            user_id=user_id,
            encrypted_data=encrypted_data,
            creation_time=now,
            expiration_time=expiration
        )
        
        self.sessions[session_id] = session
        return session_id
    
    def get_session_data(self, session_id: str) -> str:
        if not session_id or not self._is_valid_session_id(session_id):
            raise ValueError("Invalid session_id")
        
        session = self.sessions.get(session_id)
        if session is None:
            raise RuntimeError("Session not found")
        
        now = time.time()
        if now > session.expiration_time:
            del self.sessions[session_id]
            raise RuntimeError("Session expired")
        
        return self._decrypt_data(session.encrypted_data)
    
    def terminate_session(self, session_id: str) -> bool:
        if not session_id or not self._is_valid_session_id(session_id):
            return False
        
        if session_id in self.sessions:
            del self.sessions[session_id]
            return True
        return False
    
    def cleanup_expired_sessions(self) -> None:
        now = time.time()
        expired = [sid for sid, session in self.sessions.items() 
                   if now > session.expiration_time]
        for sid in expired:
            del self.sessions[sid]
    
    def _generate_secure_session_id(self) -> str:
        random_bytes = secrets.token_bytes(32)
        hash_obj = hashlib.sha256(random_bytes)
        return base64.urlsafe_b64encode(hash_obj.digest()).decode('ascii').rstrip('=')
    
    def _is_valid_session_id(self, session_id: str) -> bool:
        if len(session_id) != 43:
            return False
        allowed_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-')
        return all(c in allowed_chars for c in session_id)
    
    def _encrypt_data(self, plaintext: str) -> bytes:
        iv = secrets.token_bytes(self.GCM_IV_LENGTH)
        plaintext_bytes = plaintext.encode('utf-8')
        
        ciphertext = self.aesgcm.encrypt(iv, plaintext_bytes, None)
        return iv + ciphertext
    
    def _decrypt_data(self, encrypted_data: bytes) -> str:
        if len(encrypted_data) < self.GCM_IV_LENGTH + self.GCM_TAG_LENGTH:
            raise ValueError("Invalid encrypted data")
        
        iv = encrypted_data[:self.GCM_IV_LENGTH]
        ciphertext = encrypted_data[self.GCM_IV_LENGTH:]
        
        plaintext_bytes = self.aesgcm.decrypt(iv, ciphertext, None)
        return plaintext_bytes.decode('utf-8')


def main():
    session_manager = SessionManager()
    
    # Test 1: Create and retrieve session
    print("Test 1: Create and retrieve session")
    session_id1 = session_manager.create_session("user123", "userData1")
    print(f"Session created: {session_id1}")
    data1 = session_manager.get_session_data(session_id1)
    print(f"Retrieved data: {data1}")
    print(f"Test 1 passed: {data1 == 'userData1'}")
    
    # Test 2: Multiple sessions
    print("\\nTest 2: Multiple sessions")
    session_id2 = session_manager.create_session("user456", "userData2")
    session_id3 = session_manager.create_session("user789", "userData3")
    print(f"Sessions are unique: {session_id1 != session_id2 and session_id2 != session_id3}")
    
    # Test 3: Terminate session
    print("\\nTest 3: Terminate session")
    terminated = session_manager.terminate_session(session_id1)
    print(f"Session terminated: {terminated}")
    try:
        session_manager.get_session_data(session_id1)
        print("Test 3 failed: Session should not exist")
    except RuntimeError as e:
        print(f"Test 3 passed: {e}")
    
    # Test 4: Invalid session ID
    print("\\nTest 4: Invalid session ID")
    try:
        session_manager.get_session_data("invalid-session-id")
        print("Test 4 failed: Should reject invalid session ID")
    except ValueError as e:
        print(f"Test 4 passed: {e}")
    
    # Test 5: Cleanup expired sessions
    print("\\nTest 5: Active sessions cleanup")
    session_manager.cleanup_expired_sessions()
    data2 = session_manager.get_session_data(session_id2)
    print(f"Test 5 passed: Active session still accessible: {data2 == 'userData2'}")


if __name__ == "__main__":
    main()
