import time
import hmac
import secrets
from typing import Dict

class Session:
    __slots__ = ("user", "expires_at", "last_access")
    def __init__(self, user: str, expires_at: int, last_access: int) -> None:
        self.user = user
        self.expires_at = expires_at
        self.last_access = last_access

class SessionManager:
    def __init__(self) -> None:
        self._sessions: Dict[str, Session] = {}

    def add_session(self, token: str, user: str, ttl_seconds: int) -> bool:
        if not _is_valid_token(token) or not _is_valid_user(user):
            return False
        ttl = _clamp_ttl(ttl_seconds)
        if ttl <= 0:
            return False
        if token in self._sessions:
            return False
        now = _now_seconds()
        self._sessions[token] = Session(user, now + ttl, now)
        return True

    def validate_session(self, token: str) -> str:
        if not _is_valid_token(token):
            return ""
        s = self._sessions.get(token)
        if s is None:
            return ""
        now = _now_seconds()
        if now > s.expires_at:
            self._sessions.pop(token, None)
            return ""
        s.last_access = now
        return s.user

    def refresh_session(self, old_token: str, new_token: str, ttl_seconds: int) -> bool:
        if not _is_valid_token(old_token) or not _is_valid_token(new_token):
            return False
        if hmac.compare_digest(old_token, new_token):
            return False
        s = self._sessions.get(old_token)
        if s is None:
            return False
        now = _now_seconds()
        if now > s.expires_at:
            self._sessions.pop(old_token, None)
            return False
        if new_token in self._sessions:
            return False
        ttl = _clamp_ttl(ttl_seconds)
        self._sessions[new_token] = Session(s.user, now + ttl, now)
        self._sessions.pop(old_token, None)
        return True

    def revoke_session(self, token: str) -> bool:
        if not _is_valid_token(token):
            return False
        return self._sessions.pop(token, None) is not None

    def prune_expired(self) -> int:
        now = _now_seconds()
        to_del = [t for t, s in self._sessions.items() if now > s.expires_at]
        for t in to_del:
            self._sessions.pop(t, None)
        return len(to_del)

    def count_active(self) -> int:
        self.prune_expired()
        return len(self._sessions)

def _is_valid_token(token: str) -> bool:
    if not isinstance(token, str):
        return False
    n = len(token)
    if n < 16 or n > 256:
        return False
    for ch in token:
        if not (ch.isalnum() or ch in "-_"):
            return False
    return True

def _is_valid_user(user: str) -> bool:
    if not isinstance(user, str):
        return False
    n = len(user)
    if n < 1 or n > 64:
        return False
    for ch in user:
        if not (ch.isalnum() or ch in "._-"):
            return False
    return True

def _clamp_ttl(ttl: int) -> int:
    if ttl < 1:
        return 0
    if ttl > 86400:
        return 86400
    return ttl

def _now_seconds() -> int:
    return int(time.time())

def _generate_token(nbytes: int = 32) -> str:
    if nbytes < 16:
        nbytes = 16
    if nbytes > 64:
        nbytes = 64
    return secrets.token_urlsafe(nbytes)

if __name__ == "__main__":
    mgr = SessionManager()

    # Test 1: Create and validate
    tok1 = _generate_token(32)
    add1 = mgr.add_session(tok1, "alice", 5)
    v1 = mgr.validate_session(tok1)
    print(f"T1 add={add1} validUser={v1} active={mgr.count_active()}")

    # Test 2: Refresh token
    tok2 = _generate_token(32)
    ref = mgr.refresh_session(tok1, tok2, 5)
    v_old = mgr.validate_session(tok1)
    v_new = mgr.validate_session(tok2)
    print(f"T2 refresh={ref} oldValid='{v_old}' newValid='{v_new}' active={mgr.count_active()}")

    # Test 3: Revoke
    rev = mgr.revoke_session(tok2)
    v3 = mgr.validate_session(tok2)
    print(f"T3 revoke={rev} postRevokeValid='{v3}' active={mgr.count_active()}")

    # Test 4: Expiration
    tok3 = _generate_token(24)
    add2 = mgr.add_session(tok3, "bob", 1)
    time.sleep(1.5)
    mgr.prune_expired()
    v4 = mgr.validate_session(tok3)
    print(f"T4 add={add2} afterExpireValid='{v4}' active={mgr.count_active()}")

    # Test 5: Invalid token
    add_bad = mgr.add_session("short", "charlie", 10)
    print(f"T5 invalidTokenAdd={add_bad} active={mgr.count_active()}")