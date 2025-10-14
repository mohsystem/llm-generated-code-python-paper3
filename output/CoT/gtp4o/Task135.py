import base64
import hmac
import os
import time
from hashlib import sha256

class CsrfProtector:
    def __init__(self, ttl_seconds: int, expected_origin: str):
        self.ttl_seconds = ttl_seconds
        self.expected_origin = expected_origin
        self._secret = os.urandom(32)
        # session_id -> { nonce: issued_at }
        self._used_nonces = {}

    def generate_token(self, session_id: str) -> str:
        now = int(time.time())
        return self.generate_token_at(session_id, now)

    def generate_token_at(self, session_id: str, issued_at: int) -> str:
        nonce = base64.urlsafe_b64encode(os.urandom(16)).rstrip(b'=').decode('ascii')
        payload = f"{session_id}:{issued_at}:{nonce}".encode('utf-8')
        sig = base64.urlsafe_b64encode(hmac.new(self._secret, payload, sha256).digest()).rstrip(b'=').decode('ascii')
        return f"{issued_at}.{nonce}.{sig}"

    def validate_request(self, method: str, session_id: str, token: str, origin_header: str, referer_header: str) -> bool:
        if not self._is_state_changing(method):
            return True
        if not self._validate_origin_referer(origin_header, referer_header):
            return False
        if not token or not session_id:
            return False
        parts = token.split(".")
        if len(parts) != 3:
            return False
        try:
            ts = int(parts[0])
        except ValueError:
            return False
        nonce = parts[1]
        sig = parts[2]
        now = int(time.time())
        if ts > now or (now - ts) > self.ttl_seconds:
            return False

        payload = f"{session_id}:{ts}:{nonce}".encode('utf-8')
        expected_sig = base64.urlsafe_b64encode(hmac.new(self._secret, payload, sha256).digest()).rstrip(b'=').decode('ascii')
        if not hmac.compare_digest(expected_sig, sig):
            return False

        # replay protection
        store = self._used_nonces.setdefault(session_id, {})
        if nonce in store:
            return False
        store[nonce] = ts
        # cleanup
        for k in list(store.keys()):
            if now - store[k] > self.ttl_seconds * 2:
                del store[k]
        return True

    def _is_state_changing(self, method: str) -> bool:
        if not method:
            return False
        m = method.upper()
        return m in ("POST", "PUT", "PATCH", "DELETE")

    def _validate_origin_referer(self, origin_header: str, referer_header: str) -> bool:
        if not self.expected_origin:
            return True
        if origin_header:
            return origin_header == self.expected_origin
        if referer_header:
            return referer_header.startswith(self.expected_origin)
        return False

def main():
    protector = CsrfProtector(ttl_seconds=5, expected_origin="https://example.com")
    session = "session-xyz"
    token = protector.generate_token(session)

    t1 = protector.validate_request("POST", session, token, "https://example.com", None)
    t2 = protector.validate_request("POST", session, token, "https://evil.com", None)
    tampered = token[:-1] + ("A" if token[-1] != "A" else "B")
    t3 = protector.validate_request("POST", session, tampered, "https://example.com", None)
    expired = protector.generate_token_at(session, int(time.time()) - 3600)
    t4 = protector.validate_request("POST", session, expired, "https://example.com", None)
    t5 = protector.validate_request("POST", session, token, "https://example.com", None)

    print("T1_valid=", t1)
    print("T2_bad_origin=", t2)
    print("T3_tampered=", t3)
    print("T4_expired=", t4)
    print("T5_replay=", t5)

if __name__ == "__main__":
    main()