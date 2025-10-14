
import secrets
import time
from typing import Optional, Dict
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

SESSION_TIMEOUT_SECONDS = 3600
TOKEN_SIZE = 32
SALT_SIZE = 16
IV_SIZE = 12
TAG_SIZE = 16
PBKDF2_ITERATIONS = 210000


class Session:
    def __init__(self, user_id: str, encrypted_data: bytes, expiry_time: int, salt: bytes, iv: bytes):
        self.user_id = user_id
        self.encrypted_data = encrypted_data
        self.expiry_time = expiry_time
        self.salt = salt
        self.iv = iv


class SessionManager:
    def __init__(self):
        self.sessions: Dict[str, Session] = {}
    
    def create_session(self, user_id: str, session_data: str, master_key: str) -> Optional[str]:
        if not user_id or not isinstance(user_id, str) or len(user_id) > 256:
            raise ValueError("Invalid user_id")
        if not session_data or not isinstance(session_data, str) or len(session_data) > 10000:
            raise ValueError("Invalid session_data")
        if not master_key or not isinstance(master_key, str) or len(master_key) < 16:
            raise ValueError("Invalid master_key")
        
        try:
            session_token = secrets.token_bytes(TOKEN_SIZE)
            token_hex = session_token.hex()
            
            salt = secrets.token_bytes(SALT_SIZE)
            iv = secrets.token_bytes(IV_SIZE)
            
            key = self._derive_key(master_key, salt)
            encrypted_data = self._encrypt_aes(session_data.encode('utf-8'), key, iv)
            
            expiry_time = int(time.time()) + SESSION_TIMEOUT_SECONDS
            
            session = Session(user_id, encrypted_data, expiry_time, salt, iv)
            self.sessions[token_hex] = session
            
            return token_hex
        except Exception:
            raise RuntimeError("Session creation failed")
    
    def get_session_data(self, token: str, master_key: str) -> Optional[str]:
        if not token or not isinstance(token, str) or len(token) != TOKEN_SIZE * 2:
            return None
        if not master_key or not isinstance(master_key, str) or len(master_key) < 16:
            return None
        
        session = self.sessions.get(token)
        if session is None:
            return None
        
        if int(time.time()) > session.expiry_time:
            del self.sessions[token]
            return None
        
        try:
            key = self._derive_key(master_key, session.salt)
            decrypted_data = self._decrypt_aes(session.encrypted_data, key, session.iv)
            return decrypted_data.decode('utf-8')
        except Exception:
            return None
    
    def invalidate_session(self, token: str) -> bool:
        if not token or not isinstance(token, str) or len(token) != TOKEN_SIZE * 2:
            return False
        return self.sessions.pop(token, None) is not None
    
    def validate_session(self, token: str) -> bool:
        if not token or not isinstance(token, str) or len(token) != TOKEN_SIZE * 2:
            return False
        
        session = self.sessions.get(token)
        if session is None:
            return False
        
        if int(time.time()) > session.expiry_time:
            del self.sessions[token]
            return False
        
        return True
    
    def _derive_key(self, passphrase: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(passphrase.encode('utf-8'))
    
    def _encrypt_aes(self, plaintext: bytes, key: bytes, iv: bytes) -> bytes:
        aesgcm = AESGCM(key)
        return aesgcm.encrypt(iv, plaintext, None)
    
    def _decrypt_aes(self, ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(iv, ciphertext, None)


def main():
    manager = SessionManager()
    master_key = "securemaster_passphrase_key_2024"
    
    print("Test 1: Create and validate session")
    token1 = manager.create_session("user123", "sessionData1", master_key)
    print(f"Created token: {token1[:16]}...")
    print(f"Valid: {manager.validate_session(token1)}")
    
    print("\\nTest 2: Retrieve session data")
    data = manager.get_session_data(token1, master_key)
    print(f"Retrieved data: {data}")
    
    print("\\nTest 3: Invalidate session")
    invalidated = manager.invalidate_session(token1)
    print(f"Invalidated: {invalidated}")
    print(f"Still valid: {manager.validate_session(token1)}")
    
    print("\\nTest 4: Multiple sessions")
    token2 = manager.create_session("user456", "sessionData2", master_key)
    token3 = manager.create_session("user789", "sessionData3", master_key)
    print(f"Token2 valid: {manager.validate_session(token2)}")
    print(f"Token3 valid: {manager.validate_session(token3)}")
    
    print("\\nTest 5: Invalid token handling")
    valid_invalid = manager.validate_session("invalidtoken123")
    print(f"Invalid token valid: {valid_invalid}")


if __name__ == "__main__":
    main()
