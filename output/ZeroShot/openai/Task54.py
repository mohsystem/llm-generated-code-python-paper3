import os
import time
import secrets
import hashlib
import hmac

class Task54:
    SALT_LEN = 16
    HASH_LEN = 32
    PBKDF2_ITER = 120_000
    OTP_TTL_SECONDS = 120  # 2 minutes

    def __init__(self):
        self.users = {}        # username -> {salt: bytes, hash: bytes, iter: int}
        self.pending = {}      # username -> {otp: str, exp: float, used: bool}

    @staticmethod
    def _hash_password(password: str, salt: bytes, iterations: int) -> bytes:
        return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, dklen=Task54.HASH_LEN)

    @staticmethod
    def _ct_eq(a: bytes, b: bytes) -> bool:
        return hmac.compare_digest(a, b)

    @staticmethod
    def _ct_eq_str(a: str, b: str) -> bool:
        return hmac.compare_digest(a.encode('utf-8'), b.encode('utf-8'))

    def register_user(self, username: str, password: str) -> bool:
        if not username or len(username) > 64 or not password or len(password) < 8:
            return False
        if username in self.users:
            return False
        salt = os.urandom(self.SALT_LEN)
        pw_hash = self._hash_password(password, salt, self.PBKDF2_ITER)
        self.users[username] = {'salt': salt, 'hash': pw_hash, 'iter': self.PBKDF2_ITER}
        return True

    def login_request(self, username: str, password: str):
        u = self.users.get(username)
        if not u:
            return None
        cand = self._hash_password(password, u['salt'], u['iter'])
        if not self._ct_eq(cand, u['hash']):
            return None
        otp = f"{secrets.randbelow(1_000_000):06d}"
        self.pending[username] = {'otp': otp, 'exp': time.time() + self.OTP_TTL_SECONDS, 'used': False}
        return otp

    def verify_otp(self, username: str, otp: str) -> bool:
        po = self.pending.get(username)
        if not po:
            return False
        if po['used'] or time.time() > po['exp']:
            self.pending.pop(username, None)
            return False
        ok = self._ct_eq_str(po['otp'], otp)
        if ok:
            po['used'] = True
            self.pending.pop(username, None)
            return True
        return False

if __name__ == "__main__":
    t = Task54()

    # Test 1: Successful login with correct password and OTP
    print("Register alice:", t.register_user("alice", "password123"))
    otp1 = t.login_request("alice", "password123")
    print("OTP issued (alice):", otp1 if otp1 else "None")
    print("Verify correct OTP (alice):", t.verify_otp("alice", otp1 if otp1 else ""))

    # Test 2: Wrong password
    otp_wrong = t.login_request("alice", "wrongpass!")
    print("Login with wrong password returns OTP?", otp_wrong is not None)

    # Test 3: Wrong OTP
    otp2 = t.login_request("alice", "password123")
    print("OTP issued (alice) second time:", otp2 if otp2 else "None")
    print("Verify wrong OTP (alice):", t.verify_otp("alice", "000000"))

    # Test 4: Nonexistent user
    otp_no_user = t.login_request("bob", "anything123")
    print("OTP issued (nonexistent user bob):", otp_no_user if otp_no_user else "None")

    # Test 5: OTP reuse should fail
    otp3 = t.login_request("alice", "password123")
    print("OTP issued (alice third time):", otp3 if otp3 else "None")
    first_use = t.verify_otp("alice", otp3 if otp3 else "")
    second_use = t.verify_otp("alice", otp3 if otp3 else "")
    print("First use success?", first_use, ", second reuse should fail:", second_use)