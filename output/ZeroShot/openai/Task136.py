import os
import hmac
import hashlib
from typing import Dict, Tuple

class Task136:
    DEFAULT_ITERATIONS = 150_000
    DEFAULT_KEYLEN = 32  # bytes
    DUMMY_SALT = b'\xab\xab6}=-\xd8\x19fAh3\'\xe5w\x94'  # 16 bytes fixed
    DUMMY_ITERATIONS = DEFAULT_ITERATIONS
    DUMMY_KEYLEN = DEFAULT_KEYLEN
    _DUMMY_HASH = None

    @staticmethod
    def _init_dummy():
        if Task136._DUMMY_HASH is None:
            Task136._DUMMY_HASH = Task136.hash_password("nottherightpassword", Task136.DUMMY_SALT, Task136.DUMMY_ITERATIONS, Task136.DUMMY_KEYLEN)

    @staticmethod
    def generate_salt(length: int = 16) -> bytes:
        if length < 16:
            length = 16
        return os.urandom(length)

    @staticmethod
    def hash_password(password: str, salt: bytes, iterations: int, keylen: int) -> bytes:
        if password is None or salt is None:
            raise ValueError("password/salt cannot be None")
        if iterations < 100_000:
            iterations = 100_000
        if keylen < 16:
            keylen = 16
        pwd = password.encode('utf-8')
        return hashlib.pbkdf2_hmac('sha256', pwd, salt, iterations, dklen=keylen)

    @staticmethod
    def constant_time_equals(a: bytes, b: bytes) -> bool:
        if a is None or b is None:
            return False
        return hmac.compare_digest(a, b)

    # db maps username -> (salt, hash, iterations, keylen)
    @staticmethod
    def register_user(db: Dict[str, Tuple[bytes, bytes, int, int]], username: str, password: str, iterations: int = None, keylen: int = None) -> bool:
        if db is None or username is None or password is None:
            return False
        if not username or len(username) > 64:
            return False
        if username in db:
            return False
        iterations = iterations or Task136.DEFAULT_ITERATIONS
        keylen = keylen or Task136.DEFAULT_KEYLEN
        salt = Task136.generate_salt(16)
        phash = Task136.hash_password(password, salt, iterations, keylen)
        db[username] = (salt, phash, iterations, keylen)
        return True

    @staticmethod
    def authenticate(db: Dict[str, Tuple[bytes, bytes, int, int]], username: str, password: str) -> bool:
        if db is None or username is None or password is None:
            return False
        Task136._init_dummy()
        rec = db.get(username)
        if rec is None:
            computed = Task136.hash_password(password, Task136.DUMMY_SALT, Task136.DUMMY_ITERATIONS, Task136.DUMMY_KEYLEN)
            # compare with dummy for timing, but always return False
            _ = Task136.constant_time_equals(computed, Task136._DUMMY_HASH)
            return False
        salt, phash, iters, keylen = rec
        computed = Task136.hash_password(password, salt, iters, keylen)
        return Task136.constant_time_equals(computed, phash)


if __name__ == "__main__":
    db = {}
    Task136.register_user(db, "alice", "Alic3-Strong_P@ss!")
    Task136.register_user(db, "bob", "CorrectHorseBatteryStaple123!")
    Task136.register_user(db, "carol", "S0mething@Secure")

    t1 = Task136.authenticate(db, "alice", "Alic3-Strong_P@ss!")  # True
    t2 = Task136.authenticate(db, "alice", "wrong_password")      # False
    t3 = Task136.authenticate(db, "unknown", "whatever")          # False
    t4 = Task136.authenticate(db, "bob", "CorrectHorseBatteryStaple123!")  # True
    t5 = Task136.authenticate(db, "carol", "WrongOne!")           # False

    print("Test1 (alice correct):", t1)
    print("Test2 (alice wrong):", t2)
    print("Test3 (unknown user):", t3)
    print("Test4 (bob correct):", t4)
    print("Test5 (carol wrong):", t5)