import base64
import secrets
import time
from typing import Dict


class CsrfTokenStore:
    def __init__(self, ttl_seconds: int = 600) -> None:
        if not (1 <= ttl_seconds <= 86400):
            raise ValueError("Invalid TTL")
        self._ttl = ttl_seconds
        self._store: Dict[str, Dict[str, int]] = {}

    @staticmethod
    def _valid_session_id(session_id: str) -> bool:
        if not isinstance(session_id, str):
            return False
        if not (1 <= len(session_id) <= 64):
            return False
        for ch in session_id:
            if not (ch.isalpha() or ch.isdigit() or ch in "-_"):
                return False
        return True

    @staticmethod
    def _now() -> int:
        return int(time.time())

    def _purge(self) -> None:
        now = self._now()
        to_delete_sessions = []
        for sid, tokens in self._store.items():
            expired = [t for t, exp in tokens.items() if exp <= now]
            for t in expired:
                del tokens[t]
            if not tokens:
                to_delete_sessions.append(sid)
        for sid in to_delete_sessions:
            del self._store[sid]

    def generate_token(self, session_id: str) -> str:
        if not self._valid_session_id(session_id):
            raise ValueError("Invalid session_id")
        # 32 bytes of randomness, URL-safe, no secrets printed
        token = secrets.token_urlsafe(32)
        exp = self._now() + self._ttl
        self._store.setdefault(session_id, {})[token] = exp
        self._purge()
        return token

    def validate_token(self, session_id: str, token: str) -> bool:
        if not self._valid_session_id(session_id):
            return False
        if not isinstance(token, str) or not (16 <= len(token) <= 256):
            return False
        tokens = self._store.get(session_id)
        if not tokens:
            self._purge()
            return False
        exp = tokens.get(token)
        now = self._now()
        if exp is None:
            self._purge()
            return False
        if exp <= now:
            del tokens[token]
            if not tokens:
                del self._store[session_id]
            self._purge()
            return False
        # One-time use to prevent replay
        del tokens[token]
        if not tokens:
            del self._store[session_id]
        self._purge()
        return True

    # Test helper: force expire a token
    def expire_token_for_test(self, session_id: str, token: str) -> bool:
        tokens = self._store.get(session_id)
        if not tokens or token not in tokens:
            return False
        tokens[token] = self._now() - 1
        return True


def main() -> None:
    store = CsrfTokenStore(600)

    # Test 1: Valid token for the session
    s1 = "sessA"
    tok1 = store.generate_token(s1)
    t1 = store.validate_token(s1, tok1)
    print(t1)

    # Test 2: Token used with wrong session
    s2 = "sessB"
    t2 = store.validate_token(s2, tok1)
    print(t2)

    # Test 3: Tampered token fails
    tok3 = store.generate_token(s1)
    tampered = ("A" if tok3[0] != "A" else "B") + tok3[1:]
    t3 = store.validate_token(s1, tampered)
    print(t3)

    # Test 4: Expired token fails
    tok4 = store.generate_token("sessX")
    store.expire_token_for_test("sessX", tok4)
    t4 = store.validate_token("sessX", tok4)
    print(t4)

    # Test 5: Replay fails on second use
    tok5 = store.generate_token("sessY")
    first = store.validate_token("sessY", tok5)
    second = store.validate_token("sessY", tok5)
    t5 = first and not second
    print(t5)


if __name__ == "__main__":
    main()