# Chain-of-Through Step 1: Problem understanding
# Implement 2FA using securely generated numeric OTPs with expiry and attempt limits.

# Chain-of-Through Step 2: Security requirements
# - Use secrets for cryptographically strong randomness
# - Use hmac.compare_digest for constant-time compare
# - Enforce OTP expiration and attempt limits
# - Avoid leaking OTPs (printed only for test/demo)

import time
import secrets
import hmac

class TwoFAService:
    def __init__(self, otp_length: int = 6, ttl_seconds: float = 120.0, max_attempts: int = 3):
        if otp_length < 4 or otp_length > 12:
            raise ValueError("OTP length out of bounds")
        if ttl_seconds < 1.0:
            raise ValueError("TTL too short")
        if max_attempts < 1:
            raise ValueError("Attempts must be >=1")
        self.otp_length = otp_length
        self.ttl_seconds = ttl_seconds
        self.max_attempts = max_attempts
        self._records = {}  # user_id -> dict

    @staticmethod
    def _ct_eq(a: str, b: str) -> bool:
        if a is None or b is None:
            return False
        return hmac.compare_digest(a.encode(), b.encode())

    def generate_otp(self, user_id: str) -> str:
        if not user_id:
            raise ValueError("user_id required")
        # Generate per-digit to avoid modulo bias
        otp = ''.join(str(secrets.randbelow(10)) for _ in range(self.otp_length))
        self._records[user_id] = {
            'otp': otp,
            'expires_at': time.time() + self.ttl_seconds,
            'attempts_left': self.max_attempts,
            'valid': True
        }
        return otp  # In production, send via secure channel

    def verify_otp(self, user_id: str, otp_input: str) -> bool:
        rec = self._records.get(user_id)
        now = time.time()
        if not rec or not rec['valid']:
            return False
        if now > rec['expires_at']:
            rec['valid'] = False
            return False
        if rec['attempts_left'] <= 0:
            rec['valid'] = False
            return False
        ok = self._ct_eq(rec['otp'], otp_input)
        if ok:
            rec['valid'] = False
            return True
        else:
            rec['attempts_left'] -= 1
            if rec['attempts_left'] <= 0:
                rec['valid'] = False
            return False

    # Test helper
    def expire_now_for_test(self, user_id: str):
        rec = self._records.get(user_id)
        if rec:
            rec['expires_at'] = time.time() - 1.0

class UserStore:
    def __init__(self):
        self._data = {}

    @staticmethod
    def _ct_eq(a: str, b: str) -> bool:
        return hmac.compare_digest(a.encode(), b.encode())

    def add_user(self, username: str, password: str):
        self._data[username] = password

    def verify_password(self, username: str, password: str) -> bool:
        stored = self._data.get(username)
        if stored is None:
            return False
        return self._ct_eq(stored, password)

def login_step1(user_store: UserStore, username: str, password: str) -> bool:
    return user_store.verify_password(username, password)

def main():
    # Chain-of-Through Step 3: Secure coding generation
    store = UserStore()
    store.add_user("alice", "pass123")
    store.add_user("bob", "secret!")
    store.add_user("carol", "p@ssw0rd")
    store.add_user("dave", "letmein")
    store.add_user("erin", "hunter2")

    twofa = TwoFAService(otp_length=6, ttl_seconds=2.0, max_attempts=3)

    # Test 1: Success
    pw = login_step1(store, "alice", "pass123")
    otp = twofa.generate_otp("alice") if pw else None
    print("Test1 OTP (simulated send):", otp)
    print("Test1 success:", pw and twofa.verify_otp("alice", otp))

    # Test 2: Wrong password
    pw = login_step1(store, "bob", "wrong")
    print("Test2 success (should be False):", pw)

    # Test 3: Wrong OTP
    pw = login_step1(store, "carol", "p@ssw0rd")
    otp = twofa.generate_otp("carol") if pw else None
    print("Test3 OTP (simulated send):", otp)
    print("Test3 success (should be False):", pw and twofa.verify_otp("carol", "000000"))

    # Test 4: Expired
    pw = login_step1(store, "dave", "letmein")
    otp = twofa.generate_otp("dave") if pw else None
    print("Test4 OTP (simulated send):", otp)
    twofa.expire_now_for_test("dave")
    print("Test4 success (should be False):", pw and twofa.verify_otp("dave", otp))

    # Test 5: Attempt limit exceeded
    pw = login_step1(store, "erin", "hunter2")
    otp = twofa.generate_otp("erin") if pw else None
    print("Test5 OTP (simulated send):", otp)
    a = twofa.verify_otp("erin", "111111")
    b = twofa.verify_otp("erin", "222222")
    c = twofa.verify_otp("erin", "333333")
    d = twofa.verify_otp("erin", otp)
    print("Test5 sequence (should be False,False,False,False):", a, b, c, d)

if __name__ == "__main__":
    # Chain-of-Through Step 4: Code review done via comments
    # Chain-of-Through Step 5: Secure code output
    main()