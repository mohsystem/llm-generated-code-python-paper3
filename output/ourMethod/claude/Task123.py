
#!/usr/bin/env python3
"""\nSecure user session management system.\nPrevents session fixation, hijacking, and related vulnerabilities.\n"""

import secrets
import hashlib
import hmac
import time
import json
from typing import Optional, Dict, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta


@dataclass
class Session:
    """Represents a user session with security attributes."""
    session_id: str
    user_id: str
    created_at: float
    last_activity: float
    ip_address: str
    user_agent_hash: str  # Hashed to avoid storing full user agent
    

class SessionManager:
    """\n    Secure session manager with protection against:\n    - Session fixation (new ID on login)\n    - Session hijacking (fingerprinting)\n    - Timing attacks (constant-time comparison)\n    - Brute force (secure random IDs)\n    """
    
    def __init__(
        self, 
        session_timeout: int = 1800,  # 30 minutes in seconds
        absolute_timeout: int = 43200  # 12 hours in seconds
    ):
        """\n        Initialize session manager with security parameters.\n        \n        Args:\n            session_timeout: Idle timeout in seconds\n            absolute_timeout: Maximum session lifetime in seconds\n        """
        # Input validation: ensure timeouts are positive integers
        if not isinstance(session_timeout, int) or session_timeout <= 0:
            raise ValueError("session_timeout must be a positive integer")
        if not isinstance(absolute_timeout, int) or absolute_timeout <= 0:
            raise ValueError("absolute_timeout must be a positive integer")
        
        self._sessions: Dict[str, Session] = {}
        self._session_timeout = session_timeout
        self._absolute_timeout = absolute_timeout
        # Use secrets module for cryptographically secure secret key
        self._hmac_key = secrets.token_bytes(32)
    
    def create_session(
        self, 
        user_id: str, 
        ip_address: str, 
        user_agent: str
    ) -> str:
        """\n        Create a new session with cryptographically secure ID.\n        Prevents session fixation by generating unpredictable IDs.\n        \n        Args:\n            user_id: User identifier (validated externally)\n            ip_address: Client IP address for fingerprinting\n            user_agent: Client user agent for fingerprinting\n            \n        Returns:\n            Secure session ID\n        """
        # Input validation: ensure all parameters are non-empty strings
        if not isinstance(user_id, str) or not user_id.strip():
            raise ValueError("user_id must be a non-empty string")
        if not isinstance(ip_address, str) or not ip_address.strip():
            raise ValueError("ip_address must be a non-empty string")
        if not isinstance(user_agent, str) or not user_agent.strip():
            raise ValueError("user_agent must be a non-empty string")
        
        # Validate user_id length to prevent abuse
        if len(user_id) > 256:
            raise ValueError("user_id exceeds maximum length of 256")
        
        # Generate cryptographically secure session ID using secrets module
        # 32 bytes = 256 bits of entropy, URL-safe encoding
        session_id = secrets.token_urlsafe(32)
        
        current_time = time.time()
        
        # Hash user agent to avoid storing sensitive browser fingerprint data
        # Use SHA-256 for consistent hashing
        user_agent_hash = hashlib.sha256(
            user_agent.encode('utf-8')
        ).hexdigest()
        
        # Create session object with security metadata
        session = Session(
            session_id=session_id,
            user_id=user_id,
            created_at=current_time,
            last_activity=current_time,
            ip_address=ip_address,
            user_agent_hash=user_agent_hash
        )
        
        # Store session in memory (in production, use secure persistent storage)
        self._sessions[session_id] = session
        
        return session_id
    
    def validate_session(
        self, 
        session_id: str, 
        ip_address: str, 
        user_agent: str
    ) -> Optional[str]:
        """\n        Validate session and check for hijacking attempts.\n        Uses constant-time comparison to prevent timing attacks.\n        \n        Args:\n            session_id: Session ID to validate\n            ip_address: Current client IP\n            user_agent: Current client user agent\n            \n        Returns:\n            user_id if valid, None otherwise\n        """
        # Input validation: ensure parameters are strings
        if not isinstance(session_id, str) or not session_id:
            return None
        if not isinstance(ip_address, str) or not ip_address:
            return None
        if not isinstance(user_agent, str) or not user_agent:
            return None
        
        # Validate session_id length to prevent abuse
        if len(session_id) > 256:
            return None
        
        # Retrieve session - fail closed if not found
        session = self._sessions.get(session_id)
        if session is None:
            return None
        
        current_time = time.time()
        
        # Check absolute timeout (maximum session lifetime)
        if current_time - session.created_at > self._absolute_timeout:
            self.destroy_session(session_id)
            return None
        
        # Check idle timeout
        if current_time - session.last_activity > self._session_timeout:
            self.destroy_session(session_id)
            return None
        
        # Verify IP address matches (prevents session hijacking)
        # Use constant-time comparison to prevent timing attacks
        if not hmac.compare_digest(session.ip_address, ip_address):
            # IP mismatch - potential hijacking attempt
            self.destroy_session(session_id)
            return None
        
        # Verify user agent hash matches
        user_agent_hash = hashlib.sha256(
            user_agent.encode('utf-8')
        ).hexdigest()
        
        # Use constant-time comparison for user agent hash
        if not hmac.compare_digest(session.user_agent_hash, user_agent_hash):
            # User agent mismatch - potential hijacking attempt
            self.destroy_session(session_id)
            return None
        
        # Update last activity timestamp (session still valid)
        session.last_activity = current_time
        
        return session.user_id
    
    def destroy_session(self, session_id: str) -> bool:
        """\n        Securely destroy a session.\n        \n        Args:\n            session_id: Session ID to destroy\n            \n        Returns:\n            True if destroyed, False if not found\n        """
        # Input validation
        if not isinstance(session_id, str) or not session_id:
            return False
        
        # Remove session from storage
        if session_id in self._sessions:
            del self._sessions[session_id]
            return True
        
        return False
    
    def cleanup_expired_sessions(self) -> int:
        """\n        Remove all expired sessions from storage.\n        Should be called periodically to prevent memory leaks.\n        \n        Returns:\n            Number of sessions removed\n        """
        current_time = time.time()
        expired_sessions = []
        
        # Identify expired sessions
        for session_id, session in self._sessions.items():
            # Check both absolute and idle timeouts
            if (current_time - session.created_at > self._absolute_timeout or
                current_time - session.last_activity > self._session_timeout):
                expired_sessions.append(session_id)
        
        # Remove expired sessions
        for session_id in expired_sessions:
            del self._sessions[session_id]
        
        return len(expired_sessions)
    
    def get_session_info(self, session_id: str) -> Optional[Dict[str, Any]]:
        """\n        Get session information (for debugging/admin purposes).\n        Does not expose sensitive data like HMAC key.\n        \n        Args:\n            session_id: Session ID to query\n            \n        Returns:\n            Session info dictionary or None\n        """
        # Input validation
        if not isinstance(session_id, str) or not session_id:
            return None
        
        session = self._sessions.get(session_id)
        if session is None:
            return None
        
        # Return safe session data without exposing sensitive details
        return {
            'user_id': session.user_id,
            'created_at': datetime.fromtimestamp(session.created_at).isoformat(),
            'last_activity': datetime.fromtimestamp(session.last_activity).isoformat(),
            'ip_address': session.ip_address
            # Note: Not exposing user_agent_hash or session_id for security
        }


def main():
    """Test cases demonstrating secure session management."""
    
    print("=== Secure Session Manager Test Cases ===\\n")
    
    # Initialize session manager with 5-minute idle timeout, 1-hour absolute timeout
    manager = SessionManager(session_timeout=300, absolute_timeout=3600)
    
    # Test Case 1: Create and validate a valid session
    print("Test 1: Create and validate valid session")
    session_id = manager.create_session(
        user_id="user123",
        ip_address="192.168.1.100",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    )
    print(f"  Created session: {session_id[:16]}...")
    
    user_id = manager.validate_session(
        session_id=session_id,
        ip_address="192.168.1.100",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    )
    print(f"  Validated user: {user_id}")
    assert user_id == "user123", "Session validation failed"
    print("  ✓ Pass\\n")
    
    # Test Case 2: Reject session with mismatched IP (hijacking prevention)
    print("Test 2: Reject session with different IP address")
    user_id = manager.validate_session(
        session_id=session_id,
        ip_address="192.168.1.200",  # Different IP
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    )
    print(f"  Validation result: {user_id}")
    assert user_id is None, "Should reject mismatched IP"
    print("  ✓ Pass (correctly rejected)\\n")
    
    # Test Case 3: Reject session with mismatched user agent
    print("Test 3: Reject session with different user agent")
    session_id2 = manager.create_session(
        user_id="user456",
        ip_address="10.0.0.50",
        user_agent="Chrome/120.0.0.0"
    )
    user_id = manager.validate_session(
        session_id=session_id2,
        ip_address="10.0.0.50",
        user_agent="Firefox/121.0"  # Different user agent
    )
    print(f"  Validation result: {user_id}")
    assert user_id is None, "Should reject mismatched user agent"
    print("  ✓ Pass (correctly rejected)\\n")
    
    # Test Case 4: Destroy session and verify it's invalid\n    print("Test 4: Destroy session")\n    session_id3 = manager.create_session(\n        user_id="user789",\n        ip_address="172.16.0.10",\n        user_agent="Safari/17.0"\n    )\n    destroyed = manager.destroy_session(session_id3)\n    print(f"  Session destroyed: {destroyed}")\n    \n    user_id = manager.validate_session(\n        session_id=session_id3,\n        ip_address="172.16.0.10",\n        user_agent="Safari/17.0"\n    )\n    print(f"  Validation after destroy: {user_id}")\n    assert user_id is None, "Destroyed session should be invalid"\n    print("  ✓ Pass\\n")\n    \n    # Test Case 5: Get session information\n    print("Test 5: Retrieve session information")\n    session_id4 = manager.create_session(\n        user_id="admin001",\n        ip_address="192.168.1.1",\n        user_agent="Admin Browser/1.0"\n    )\n    info = manager.get_session_info(session_id4)\n    print(f"  Session info: {json.dumps(info, indent=4)}")\n    assert info is not None and info['user_id'] == "admin001", "Failed to get session info"
    print("  ✓ Pass\\n")
    
    # Test Case 6: Input validation
    print("Test 6: Input validation for empty/invalid inputs")
    try:
        manager.create_session("", "192.168.1.1", "Browser")
        print("  ✗ Failed to reject empty user_id")
    except ValueError:
        print("  ✓ Correctly rejected empty user_id")
    
    result = manager.validate_session("", "192.168.1.1", "Browser")
    assert result is None, "Should reject empty session_id"
    print("  ✓ Correctly rejected empty session_id")
    print("  ✓ Pass\\n")
    
    print("=== All test cases passed ===")


if __name__ == "__main__":
    main()
