
import secrets
import time
from typing import Optional, Dict
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64


class SessionManager:
    GCM_IV_LENGTH = 12
    GCM_TAG_LENGTH = 16
    SESSION_TIMEOUT_SECONDS = 3600
    
    def __init__(self, master_password: str):
        if not master_password or len(master_password) < 8:
            raise ValueError("Master password must be at least 8 characters")
        
        self._sessions: Dict[str, dict] = {}
        self._encryption_key = self._derive_key(master_password)
        self._aesgcm = AESGCM(self._encryption_key)
    
    def _derive_key(self, password: str) -> bytes:
        salt = b'fixed_salt_for_demo_only_use_random'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=210000,
        )
        return kdf.derive(password.encode('utf-8'))
    
    def create_session(self, user_id: str, session_data: str) -> str:
        if not user_id or len(user_id) > 256:
            raise ValueError("Invalid user ID")
        if not session_data or len(session_data) > 10000:
            raise ValueError("Invalid session data")
        
        now = int(time.time())
        expires_at = now + self.SESSION_TIMEOUT_SECONDS
        
        encrypted_data = self._encrypt_aes(session_data.encode('utf-8'))
        
        session_id_bytes = secrets.token_bytes(32)
        session_id = base64.urlsafe_b64encode(session_id_bytes).decode('utf-8').rstrip('=')
        
        self._sessions[session_id] = {
            'user_id': user_id,
            'created_at': now,
            'expires_at': expires_at,
            'encrypted_data': encrypted_data
        }
        
        return session_id
    
    def validate_session(self, session_id: str) -> Optional[str]:
        if not session_id:
            raise ValueError("Session ID cannot be null or empty")
        
        session = self._sessions.get(session_id)
        if not session:
            return None
        
        now = int(time.time())
        if now > session['expires_at']:
            del self._sessions[session_id]
            return None
        
        return session['user_id']
    
    def get_session_data(self, session_id: str) -> Optional[str]:
        if not session_id:
            raise ValueError("Session ID cannot be null or empty")
        
        session = self._sessions.get(session_id)
        if not session:
            return None
        
        now = int(time.time())
        if now > session['expires_at']:
            del self._sessions[session_id]
            return None
        
        decrypted_data = self._decrypt_aes(session['encrypted_data'])
        return decrypted_data.decode('utf-8')
    
    def destroy_session(self, session_id: str) -> bool:
        if not session_id:
            return False
        
        if session_id in self._sessions:
            del self._sessions[session_id]
            return True
        return False
    
    def _encrypt_aes(self, plaintext: bytes) -> bytes:
        iv = secrets.token_bytes(self.GCM_IV_LENGTH)
        ciphertext = self._aesgcm.encrypt(iv, plaintext, None)
        return iv + ciphertext
    
    def _decrypt_aes(self, encrypted_data: bytes) -> bytes:
        if len(encrypted_data) < self.GCM_IV_LENGTH + self.GCM_TAG_LENGTH:
            raise ValueError("Invalid encrypted data length")
        
        iv = encrypted_data[:self.GCM_IV_LENGTH]
        ciphertext = encrypted_data[self.GCM_IV_LENGTH:]
        
        return self._aesgcm.decrypt(iv, ciphertext, None)


def main():
    try:
        print("Test 1: Create and validate session")
        manager = SessionManager("SecurePass123!")
        session_id = manager.create_session("user001", "User session data")
        user_id = manager.validate_session(session_id)
        print(f"Session valid: {user_id is not None and user_id == 'user001'}")
        
        print("\\nTest 2: Retrieve session data")
        data = manager.get_session_data(session_id)
        print(f"Data retrieved: {data is not None and data == 'User session data'}")
        
        print("\\nTest 3: Destroy session")
        destroyed = manager.destroy_session(session_id)
        print(f"Session destroyed: {destroyed}")
        invalid_user_id = manager.validate_session(session_id)
        print(f"Session invalid after destroy: {invalid_user_id is None}")
        
        print("\\nTest 4: Multiple sessions")
        sid1 = manager.create_session("user001", "Session 1")
        sid2 = manager.create_session("user002", "Session 2")
        print(f"Multiple sessions created: {sid1 != sid2}")
        
        print("\\nTest 5: Invalid input handling")
        try:
            manager.create_session("", "data")
            print("Empty user ID rejected: False")
        except ValueError:
            print("Empty user ID rejected: True")
        
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
