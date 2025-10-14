import secrets
import time
import threading
from typing import Optional, Dict

# Chain-of-Through steps in comments:
# 1) Build a secure in-memory session manager for a web app with create, validate, get, refresh, invalidate, prune.
# 2) Security: Use secrets for token, thread-safety with Lock, expiry, rotate tokens on refresh.
# 3) Implement with careful parameter checks, no secret logging, time-constant compare helper (not required).
# 4) Reviewed for race conditions and security weaknesses.
# 5) Final secure code below.

class SessionInfo:
    def __init__(self, user_id: str, expires_at_ms: int):
        self.user_id = user_id
        self.expires_at_ms = expires_at_ms

    def __repr__(self):
        return f"SessionInfo(user_id='{self.user_id}', expires_at_ms={self.expires_at_ms})"

class Session:
    __slots__ = ("user_id", "created_at_ms", "expires_at_ms")
    def __init__(self, user_id: str, created_at_ms: int, expires_at_ms: int):
        self.user_id = user_id
        self.created_at_ms = created_at_ms
        self.expires_at_ms = expires_at_ms

class SessionManager:
    def __init__(self, ttl_ms: int = 5_000, token_bytes: int = 32):
        if ttl_ms <= 0:
            raise ValueError("ttl_ms must be > 0")
        if token_bytes < 16:
            raise ValueError("token_bytes must be >= 16")
        self._ttl_ms = ttl_ms
        self._token_bytes = token_bytes
        self._sessions: Dict[str, Session] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _now_ms() -> int:
        return int(time.time() * 1000)

    def _generate_token(self) -> str:
        # URL-safe token without padding
        return secrets.token_urlsafe(self._token_bytes)

    def create_session(self, user_id: str) -> str:
        if not user_id:
            raise ValueError("user_id required")
        token = self._generate_token()
        now = self._now_ms()
        with self._lock:
            self._sessions[token] = Session(user_id, now, now + self._ttl_ms)
        return token

    def validate_session(self, token: str) -> bool:
        if not token:
            return False
        now = self._now_ms()
        with self._lock:
            s = self._sessions.get(token)
            if s is None:
                return False
            if now > s.expires_at_ms:
                self._sessions.pop(token, None)
                return False
            return True

    def get_session_info(self, token: str) -> Optional[SessionInfo]:
        if not self.validate_session(token):
            return None
        with self._lock:
            s = self._sessions.get(token)
            if s is None:
                return None
            return SessionInfo(s.user_id, s.expires_at_ms)

    def invalidate_session(self, token: str) -> bool:
        if not token:
            return False
        with self._lock:
            return self._sessions.pop(token, None) is not None

    def refresh_session(self, token: str) -> Optional[str]:
        if not self.validate_session(token):
            return None
        now = self._now_ms()
        with self._lock:
            s = self._sessions.get(token)
            if s is None:
                return None
            new_token = self._generate_token()
            self._sessions[new_token] = Session(s.user_id, s.created_at_ms, now + self._ttl_ms)
            self._sessions.pop(token, None)
            return new_token

    def prune_expired_sessions(self) -> int:
        now = self._now_ms()
        removed = 0
        with self._lock:
            for t in list(self._sessions.keys()):
                s = self._sessions.get(t)
                if s and now > s.expires_at_ms:
                    self._sessions.pop(t, None)
                    removed += 1
        return removed

def _run_tests():
    mgr = SessionManager(ttl_ms=5000)

    # 1) Create and validate session
    t1 = mgr.create_session("alice")
    print("Test1 valid:", mgr.validate_session(t1))

    # 2) Get session info
    info = mgr.get_session_info(t1)
    print("Test2 info:", info)

    # 3) Refresh session: old invalid, new valid
    t1_new = mgr.refresh_session(t1)
    print("Test3 new valid:", mgr.validate_session(t1_new), ", old valid:", mgr.validate_session(t1))

    # 4) Invalidate session
    inv = mgr.invalidate_session(t1_new)
    print("Test4 invalidated:", inv, ", validate after:", mgr.validate_session(t1_new))

    # 5) Expiration test
    short_mgr = SessionManager(ttl_ms=100)
    t2 = short_mgr.create_session("bob")
    print("Test5 before expiry valid:", short_mgr.validate_session(t2))
    time.sleep(0.2)
    short_mgr.prune_expired_sessions()
    print("Test5 after expiry valid:", short_mgr.validate_session(t2))

if __name__ == "__main__":
    _run_tests()