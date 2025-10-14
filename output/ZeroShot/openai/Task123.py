import time
import secrets
import hmac

class SessionManager:
    MAX_TTL_SECONDS = 60 * 60 * 24 * 30  # 30 days

    def __init__(self):
        self._sessions = {}  # token -> (user_id, expiry_epoch_seconds)

    def _now(self):
        return int(time.time())

    def _ct_equal(self, a: str, b: str) -> bool:
        if a is None or b is None:
            return False
        return hmac.compare_digest(a.encode('utf-8'), b.encode('utf-8'))

    def create_session(self, user_id: str, ttl_seconds: int):
        if not user_id or not isinstance(user_id, str):
            return None
        if not isinstance(ttl_seconds, int) or ttl_seconds <= 0:
            return None
        if ttl_seconds > self.MAX_TTL_SECONDS:
            ttl_seconds = self.MAX_TTL_SECONDS
        token = secrets.token_urlsafe(32)
        while token in self._sessions:
            token = secrets.token_urlsafe(32)
        self._sessions[token] = (user_id, self._now() + ttl_seconds)
        return token

    def validate_session(self, token: str):
        if not token or not isinstance(token, str):
            return None
        entry = self._sessions.get(token)
        if not entry:
            return None
        # Defensive: confirm key identity constant-time
        for k, v in self._sessions.items():
            if v is entry:
                if not self._ct_equal(k, token):
                    return None
                break
        user_id, expiry = entry
        if self._now() > expiry:
            self._sessions.pop(token, None)
            return None
        return user_id

    def refresh_session(self, token: str, additional_ttl_seconds: int) -> bool:
        if not token or not isinstance(token, str):
            return False
        if not isinstance(additional_ttl_seconds, int) or additional_ttl_seconds <= 0:
            return False
        if additional_ttl_seconds > self.MAX_TTL_SECONDS:
            additional_ttl_seconds = self.MAX_TTL_SECONDS
        entry = self._sessions.get(token)
        if not entry:
            return False
        user_id, expiry = entry
        now = self._now()
        if now > expiry:
            self._sessions.pop(token, None)
            return False
        new_expiry = expiry + additional_ttl_seconds
        max_expiry = now + self.MAX_TTL_SECONDS
        if new_expiry > max_expiry:
            new_expiry = max_expiry
        self._sessions[token] = (user_id, new_expiry)
        return True

    def end_session(self, token: str) -> bool:
        if not token or not isinstance(token, str):
            return False
        return self._sessions.pop(token, None) is not None

    def cleanup_expired(self) -> int:
        now = self._now()
        to_remove = [t for t, (_, e) in self._sessions.items() if now > e]
        for t in to_remove:
            self._sessions.pop(t, None)
        return len(to_remove)

def main():
    mgr = SessionManager()

    # Test 1
    t1 = mgr.create_session("alice", 2)
    print("T1 token:", t1)
    print("T1 validate:", mgr.validate_session(t1))

    # Test 2
    print("T2 validate invalid:", mgr.validate_session("invalid_token"))

    # Test 3
    print("T3 refreshed:", mgr.refresh_session(t1, 5), "validate:", mgr.validate_session(t1))

    # Test 4
    print("T4 ended:", mgr.end_session(t1), "validate after end:", mgr.validate_session(t1))

    # Test 5
    t2 = mgr.create_session("bob", 1)
    print("T5 token:", t2, "validate:", mgr.validate_session(t2))
    time.sleep(2)
    print("T5 cleaned:", mgr.cleanup_expired(), "validate after expiry:", mgr.validate_session(t2))

if __name__ == "__main__":
    main()