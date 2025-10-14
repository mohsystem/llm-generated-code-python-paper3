import os
import time
import hmac
import secrets
from typing import Optional, Dict, Set

class Session:
    __slots__ = ("id", "user_id", "created_at", "expires_at", "last_accessed")
    def __init__(self, sid: str, user_id: str, created_at: int, expires_at: int):
        self.id = sid
        self.user_id = user_id
        self.created_at = created_at
        self.expires_at = expires_at
        self.last_accessed = created_at

class SessionManager:
    def __init__(self, id_bytes: int = 32):
        if id_bytes < 16:
            raise ValueError("id_bytes too small")
        self._id_bytes = id_bytes
        self._sessions: Dict[str, Session] = {}
        self._user_sessions: Dict[str, Set[str]] = {}

    def _now(self) -> int:
        return int(time.time())

    def _generate_id(self) -> str:
        # token_urlsafe returns more chars than bytes; still sufficient
        while True:
            sid = secrets.token_urlsafe(self._id_bytes)
            if sid not in self._sessions:
                return sid

    def create_session(self, user_id: str, ttl_seconds: int) -> str:
        if not user_id or ttl_seconds <= 0:
            raise ValueError("invalid input")
        sid = self._generate_id()
        now = self._now()
        s = Session(sid, user_id, now, now + ttl_seconds)
        self._sessions[sid] = s
        self._user_sessions.setdefault(user_id, set()).add(sid)
        return sid

    def _is_expired(self, s: Session, now: int) -> bool:
        return s.expires_at <= now

    def validate_session(self, session_id: str) -> bool:
        s = self._sessions.get(session_id)
        if not s:
            return False
        now = self._now()
        if self._is_expired(s, now):
            self.invalidate_session(session_id)
            return False
        s.last_accessed = now
        return True

    def get_user_for_session(self, session_id: str) -> Optional[str]:
        s = self._sessions.get(session_id)
        if not s:
            return None
        now = self._now()
        if self._is_expired(s, now):
            self.invalidate_session(session_id)
            return None
        s.last_accessed = now
        return s.user_id

    def invalidate_session(self, session_id: str) -> bool:
        s = self._sessions.pop(session_id, None)
        if s:
            us = self._user_sessions.get(s.user_id)
            if us:
                us.discard(session_id)
                if not us:
                    self._user_sessions.pop(s.user_id, None)
            return True
        return False

    def invalidate_all_sessions_for_user(self, user_id: str) -> int:
        us = self._user_sessions.pop(user_id, None)
        count = 0
        if us:
            for sid in list(us):
                if self._sessions.pop(sid, None):
                    count += 1
        return count

    def touch_session(self, session_id: str, extend_ttl_seconds: int) -> bool:
        if extend_ttl_seconds <= 0:
            return False
        s = self._sessions.get(session_id)
        if not s:
            return False
        now = self._now()
        if self._is_expired(s, now):
            self.invalidate_session(session_id)
            return False
        s.expires_at = max(s.expires_at, now) + extend_ttl_seconds
        s.last_accessed = now
        return True

    def rotate_session(self, session_id: str) -> Optional[str]:
        s = self._sessions.get(session_id)
        if not s:
            return None
        now = self._now()
        if self._is_expired(s, now):
            self.invalidate_session(session_id)
            return None
        remaining = max(0, s.expires_at - now)
        if remaining == 0:
            self.invalidate_session(session_id)
            return None
        new_id = self._generate_id()
        n = Session(new_id, s.user_id, now, now + remaining)
        self._sessions[new_id] = n
        self._user_sessions.setdefault(s.user_id, set()).add(new_id)
        self.invalidate_session(session_id)
        return new_id

    def cleanup_expired_sessions(self) -> int:
        now = self._now()
        to_remove = []
        for sid, s in self._sessions.items():
            if self._is_expired(s, now):
                to_remove.append((sid, s.user_id))
        for sid, uid in to_remove:
            self._sessions.pop(sid, None)
            us = self._user_sessions.get(uid)
            if us:
                us.discard(sid)
                if not us:
                    self._user_sessions.pop(uid, None)
        return len(to_remove)

    def secure_compare_ids(self, a: str, b: str) -> bool:
        if a is None or b is None:
            return False
        return hmac.compare_digest(a, b)

def _run_tests():
    sm = SessionManager()

    # Test 1: Create and validate
    s1 = sm.create_session("alice", 5)
    print("Test1 valid=", sm.validate_session(s1), " user=", sm.get_user_for_session(s1))

    # Test 2: Touch/extend
    print("Test2 touched=", sm.touch_session(s1, 5), " stillValid=", sm.validate_session(s1))

    # Test 3: Rotate
    rotated = sm.rotate_session(s1)
    print("Test3 oldValid=", sm.validate_session(s1), " newValid=", sm.validate_session(rotated))

    # Test 4: Expiration
    s2 = sm.create_session("bob", 1)
    time.sleep(1.5)
    print("Test4 expiredValid=", sm.validate_session(s2))

    # Test 5: Invalidate all for user
    u3s1 = sm.create_session("carol", 10)
    u3s2 = sm.create_session("carol", 10)
    invalidated = sm.invalidate_all_sessions_for_user("carol")
    print("Test5 invalidated=", invalidated, " s1Valid=", sm.validate_session(u3s1), " s2Valid=", sm.validate_session(u3s2))

if __name__ == "__main__":
    _run_tests()