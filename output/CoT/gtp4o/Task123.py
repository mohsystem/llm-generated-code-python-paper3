# Chain-of-Through Step 1: Problem understanding
# Implement a secure in-memory session manager.

# Chain-of-Through Step 2: Security requirements
# - Use secrets for CSPRNG tokens
# - Clamp TTL and validate inputs
# - Thread-safe with locks

# Chain-of-Through Step 3 & 4: Secure coding and review embedded as comments and checks

# Chain-of-Through Step 5: Final secure code

import time
import secrets
import threading

class Task123:
    TOKEN_BYTES = 32
    MAX_USERID_LEN = 128
    MIN_TTL_SEC = 1
    MAX_TTL_SEC = 7 * 24 * 60 * 60

    def __init__(self):
        self._sessions = {}
        self._lock = threading.Lock()

    def _now(self) -> int:
        return int(time.time())

    def _clamp_ttl(self, ttl: int) -> int:
        if ttl < self.MIN_TTL_SEC:
            return self.MIN_TTL_SEC
        if ttl > self.MAX_TTL_SEC:
            return self.MAX_TTL_SEC
        return ttl

    def _valid_user(self, user_id: str) -> bool:
        return isinstance(user_id, str) and 0 < len(user_id) <= self.MAX_USERID_LEN

    def _gen_token(self) -> str:
        return secrets.token_urlsafe(self.TOKEN_BYTES)

    def create_session(self, user_id: str, ttl_sec: int) -> str:
        if not self._valid_user(user_id):
            raise ValueError("Invalid user_id")
        ttl = self._clamp_ttl(int(ttl_sec))
        token = self._gen_token()
        with self._lock:
            while token in self._sessions:
                token = self._gen_token()
            now = self._now()
            self._sessions[token] = {
                "user_id": user_id,
                "created": now,
                "ttl": ttl,
                "expires": now + ttl,
            }
        return token

    def is_valid(self, token: str) -> bool:
        if not isinstance(token, str):
            return False
        with self._lock:
            s = self._sessions.get(token)
            if not s:
                return False
            if self._now() >= s["expires"]:
                del self._sessions[token]
                return False
            return True

    def refresh(self, token: str) -> bool:
        if not isinstance(token, str):
            return False
        with self._lock:
            s = self._sessions.get(token)
            if not s:
                return False
            now = self._now()
            if now >= s["expires"]:
                del self._sessions[token]
                return False
            s["expires"] = now + s["ttl"]
            return True

    def destroy(self, token: str) -> bool:
        if not isinstance(token, str):
            return False
        with self._lock:
            return self._sessions.pop(token, None) is not None

    def purge_expired(self) -> int:
        now = self._now()
        removed = 0
        with self._lock:
            for t in list(self._sessions.keys()):
                if now >= self._sessions[t]["expires"]:
                    del self._sessions[t]
                    removed += 1
        return removed

    def revoke_user_sessions(self, user_id: str) -> int:
        if not self._valid_user(user_id):
            return 0
        removed = 0
        with self._lock:
            for t, s in list(self._sessions.items()):
                if s["user_id"] == user_id:
                    del self._sessions[t]
                    removed += 1
        return removed

    def count_active(self) -> int:
        self.purge_expired()
        with self._lock:
            return len(self._sessions)

    # Test helper
    def debug_force_expire(self, token: str) -> bool:
        with self._lock:
            s = self._sessions.get(token)
            if not s:
                return False
            s["expires"] = self._now() - 1
            return True

if __name__ == "__main__":
    mgr = Task123()
    s1 = mgr.create_session("userA", 60)
    print("T1 valid:", mgr.is_valid(s1))

    s2 = mgr.create_session("userB", 5)
    mgr.debug_force_expire(s2)
    print("T2 valid after force expire:", mgr.is_valid(s2))
    print("T2 purge removed:", mgr.purge_expired())

    print("T3 refresh s1:", mgr.refresh(s1))
    print("T3 s1 still valid:", mgr.is_valid(s1))

    print("T4 destroy s1:", mgr.destroy(s1))
    print("T4 s1 valid after destroy:", mgr.is_valid(s1))

    a = mgr.create_session("userC", 10)
    b = mgr.create_session("userC", 10)
    c = mgr.create_session("userC", 10)
    print("T5 revoke userC count:", mgr.revoke_user_sessions("userC"))
    print("T5 active sessions:", mgr.count_active())