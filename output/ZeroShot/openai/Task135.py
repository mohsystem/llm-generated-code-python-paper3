import os
import hmac
import secrets
import time
from typing import Dict, Tuple

class CsrfTokenService:
    def __init__(self, ttl_seconds: float):
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self.ttl_seconds = ttl_seconds
        self._store: Dict[str, Tuple[str, float]] = {}

    def issue_token(self, session_id: str) -> str:
        if not session_id:
            raise ValueError("session_id required")
        token = secrets.token_urlsafe(32)
        expiry = time.time() + self.ttl_seconds
        self._store[session_id] = (token, expiry)
        return token

    def validate_token(self, session_id: str, provided_token: str) -> bool:
        rec = self._store.get(session_id)
        if not rec or not provided_token:
            return False
        token, expiry = rec
        now = time.time()
        if now > expiry:
            self._store.pop(session_id, None)
            return False
        ok = hmac.compare_digest(token, provided_token)
        if ok:
            # rotate on success
            new_token = secrets.token_urlsafe(32)
            self._store[session_id] = (new_token, now + self.ttl_seconds)
        return ok

    def purge_expired(self) -> int:
        now = time.time()
        to_delete = [sid for sid, (_, exp) in self._store.items() if now > exp]
        for sid in to_delete:
            self._store.pop(sid, None)
        return len(to_delete)

def main():
    service = CsrfTokenService(0.2)  # 200 ms

    # Test 1: Valid token
    s1 = "sessA"
    tok1 = service.issue_token(s1)
    r1 = service.validate_token(s1, tok1)

    # Test 2: Invalid token string
    r2 = service.validate_token(s1, "invalid")

    # Test 3: Expired token
    short = CsrfTokenService(0.01)
    s2 = "sessB"
    tok2 = short.issue_token(s2)
    time.sleep(0.03)
    r3 = short.validate_token(s2, tok2)

    # Test 4: Token cannot be used with other session
    s3 = "sessC"
    tok3 = service.issue_token(s3)
    r4 = service.validate_token("other", tok3)

    # Test 5: Replay fails after rotation
    s4 = "sessD"
    tok4 = service.issue_token(s4)
    first = service.validate_token(s4, tok4)
    second = service.validate_token(s4, tok4)
    r5 = first and not second

    print(r1)
    print(r2)
    print(r3)
    print(r4)
    print(r5)

if __name__ == "__main__":
    main()