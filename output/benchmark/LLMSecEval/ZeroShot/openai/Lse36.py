import hashlib
import hmac

ITERATIONS = 120000
KEY_LEN = 32
MAX_USERNAME_LEN = 64
MAX_PASSWORD_LEN = 128

_db = {}

def _pbkdf2(password: str, salt: bytes, iterations: int, dklen: int) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, dklen=dklen)

def _constant_time_equals(a: bytes, b: bytes) -> bool:
    if a is None or b is None:
        return False
    # hmac.compare_digest is constant-time
    return hmac.compare_digest(a, b)

def add_user(username: str, password: str, salt: bytes, iterations: int = ITERATIONS):
    pwd_hash = _pbkdf2(password, salt, iterations, KEY_LEN)
    _db[username] = {'salt': salt, 'hash': pwd_hash, 'iterations': iterations}

def login(username: str, password: str):
    if username is None or password is None:
        return None
    if not username or len(username) > MAX_USERNAME_LEN:
        return None
    if len(password) > MAX_PASSWORD_LEN:
        return None

    rec = _db.get(username)
    if not rec:
        # Dummy work to mitigate user enumeration timing
        dummy_salt = b'\xA3\x51\x5C\x09\x7E\x22\xA9\x41\x13\xF1\xB2\x08\xCD\x44\x9A\x7F'
        _constant_time_equals(_pbkdf2(password, dummy_salt, ITERATIONS, KEY_LEN),
                              _pbkdf2(password, dummy_salt, ITERATIONS, KEY_LEN))
        return None

    computed = _pbkdf2(password, rec['salt'], rec['iterations'], KEY_LEN)
    return "/home" if _constant_time_equals(computed, rec['hash']) else None

def _initialize_db():
    add_user("alice", "correct horse battery staple",
             b'\x10\x2F\x3A\x4B\x5C\x6D\x7E\x8F\x90\xAB\xBC\xCD\xDE\xEF\x01\x23', ITERATIONS)
    add_user("bob", "Tr0ub4dor&3",
             b'\x33\x55\x77\x99\xAA\xBB\xCC\xDD\xEE\xFF\x12\x34\x56\x78\x9A\xBC', ITERATIONS)

if __name__ == "__main__":
    _initialize_db()
    tests = [
        ("Test1 - correct credentials", "alice", "correct horse battery staple"),
        ("Test2 - wrong password", "alice", "wrong password"),
        ("Test3 - unknown user", "charlie", "anything"),
        ("Test4 - empty username", "", "any"),
        ("Test5 - injection-like username", "alice' OR '1'='1", "foo"),
    ]
    for label, user, pwd in tests:
        res = login(user, pwd)
        print(f"{label}: {'redirect:/home' if res == '/home' else 'no-redirect'}")