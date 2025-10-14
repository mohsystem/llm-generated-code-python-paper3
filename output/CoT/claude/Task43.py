
import secrets
import hashlib
import time
from typing import Dict, Optional
from threading import Lock

class Task43:
    SESSION_TIMEOUT_SECONDS = 1800  # 30 minutes
    SESSION_ID_LENGTH = 32
    
    def __init__(self):
        self.sessions: Dict[str, dict] = {}
        self.lock = Lock()
    
    def create_session(self, user_id: str) -> str:
        """Create a new secure session for a user"""
        if not user_id or not user_id.strip():
            raise ValueError("User ID cannot be None or empty")
        
        self._clean_expired_sessions()
        
        # Generate cryptographically secure random session ID
        random_bytes = secrets.token_bytes(self.SESSION_ID_LENGTH)
        session_id = hashlib.sha256(random_bytes).hexdigest()
        
        with self.lock:
            self.sessions[session_id] = {
                'user_id': user_id,
                'created_at': time.time(),
                'last_accessed': time.time(),
                'attributes': {}
            }
        
        return session_id
    
    def validate_session(self, session_id: str) -> bool:
        """Validate if a session is active and not expired"""
        if not session_id or not session_id.strip():
            return False
        
        with self.lock:
            if session_id not in self.sessions:
                return False
            
            session = self.sessions[session_id]
            current_time = time.time()
            
            # Check if session has expired
            if current_time - session['last_accessed'] >= self.SESSION_TIMEOUT_SECONDS:
                self.terminate_session(session_id)
                return False
            
            # Update last accessed time
            session['last_accessed'] = current_time
            return True
    
    def get_session_user_id(self, session_id: str) -> Optional[str]:
        """Get the user ID associated with a session"""
        if not self.validate_session(session_id):
            return None
        
        with self.lock:
            session = self.sessions.get(session_id)
            return session['user_id'] if session else None
    
    def terminate_session(self, session_id: str) -> None:
        """Terminate a session and cleanup resources"""
        if not session_id:
            return
        
        with self.lock:
            if session_id in self.sessions:
                # Clear sensitive data
                self.sessions[session_id]['attributes'].clear()
                del self.sessions[session_id]
    
    def set_session_attribute(self, session_id: str, key: str, value: str) -> bool:
        """Set an attribute in the session"""
        if not self.validate_session(session_id) or not key or not value:
            return False
        
        with self.lock:
            if session_id in self.sessions:
                self.sessions[session_id]['attributes'][key] = value
                return True
        return False
    
    def get_session_attribute(self, session_id: str, key: str) -> Optional[str]:
        """Get an attribute from the session"""
        if not self.validate_session(session_id) or not key:
            return None
        
        with self.lock:
            session = self.sessions.get(session_id)
            if session:
                return session['attributes'].get(key)
        return None
    
    def _clean_expired_sessions(self) -> None:
        """Clean up expired sessions"""
        current_time = time.time()
        with self.lock:
            expired_sessions = [
                sid for sid, session in self.sessions.items()
                if current_time - session['last_accessed'] >= self.SESSION_TIMEOUT_SECONDS
            ]
            for sid in expired_sessions:
                self.terminate_session(sid)


def main():
    print("=== Secure Session Management Test Cases ===\\n")
    
    manager = Task43()
    
    # Test Case 1: Create session for user
    print("Test 1: Create session")
    session_id1 = manager.create_session("user123")
    print(f"Session created: {session_id1}")
    print(f"Valid: {manager.validate_session(session_id1)}\\n")
    
    # Test Case 2: Validate existing session
    print("Test 2: Validate session")
    is_valid = manager.validate_session(session_id1)
    print(f"Session valid: {is_valid}")
    print(f"User ID: {manager.get_session_user_id(session_id1)}\\n")
    
    # Test Case 3: Set and get session attributes
    print("Test 3: Session attributes")
    manager.set_session_attribute(session_id1, "role", "admin")
    manager.set_session_attribute(session_id1, "preference", "dark_mode")
    print(f"Role: {manager.get_session_attribute(session_id1, 'role')}")
    print(f"Preference: {manager.get_session_attribute(session_id1, 'preference')}\\n")
    
    # Test Case 4: Multiple sessions
    print("Test 4: Multiple sessions")
    session_id2 = manager.create_session("user456")
    session_id3 = manager.create_session("user789")
    print(f"Session 2 created: {session_id2}")
    print(f"Session 3 created: {session_id3}")
    print(f"Session 1 valid: {manager.validate_session(session_id1)}")
    print(f"Session 2 valid: {manager.validate_session(session_id2)}")
    print(f"Session 3 valid: {manager.validate_session(session_id3)}\\n")
    
    # Test Case 5: Terminate session
    print("Test 5: Terminate session")
    manager.terminate_session(session_id1)
    print(f"Session 1 after termination: {manager.validate_session(session_id1)}")
    print(f"Session 2 still valid: {manager.validate_session(session_id2)}")
    print(f"Session 3 still valid: {manager.validate_session(session_id3)}")
    
    # Cleanup
    manager.terminate_session(session_id2)
    manager.terminate_session(session_id3)


if __name__ == "__main__":
    main()
