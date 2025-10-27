import hmac
import hashlib
import secrets
import urllib.parse
import re

class UserRecord:
    def __init__(self, salt: bytes, hash_bytes: bytes, iterations: int):
        self.salt = bytes(salt)
        self.hash = bytes(hash_bytes)
        self.iterations = int(iterations)

def is_password_valid_policy(pwd: str) -> bool:
    if pwd is None:
        return False
    if len(pwd) < 12 or len(pwd) > 128:
        return False
    has_u = any(c.isupper() for c in pwd)
    has_l = any(c.islower() for c in pwd)
    has_d = any(c.isdigit() for c in pwd)
    has_s = any(not c.isalnum() for c in pwd)
    return has_u and has_l and has_d and has_s

_USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{3,64}$")

def is_username_valid(u: str) -> bool:
    return u is not None and _USERNAME_RE.fullmatch(u) is not None

def pbkdf2(password: str, salt: bytes, iterations: int, dk_len: int = 32) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=dk_len)

def create_user_record(password: str, iterations: int = 210_000) -> UserRecord:
    salt = secrets.token_bytes(16)
    dk = pbkdf2(password, salt, iterations, 32)
    return UserRecord(salt, dk, iterations)

def verify_password(password: str, rec: UserRecord) -> bool:
    if rec is None or password is None:
        return False
    derived = pbkdf2(password, rec.salt, rec.iterations, 32)
    ok = hmac.compare_digest(derived, rec.hash)
    return ok

def parse_url(url: str):
    if url is None or len(url) > 2048:
        return None, {}
    try:
        u = urllib.parse.urlsplit(url)
        path = u.path or "/"
        if len(path) > 256:
            return None, {}
        # Safe parse query with limits
        pairs = urllib.parse.parse_qsl(u.query, keep_blank_values=True, max_num_fields=10, encoding="utf-8", errors="strict")
        params = {}
        for k, v in pairs:
            if len(k) > 256 or len(v) > 256:
                return None, {}
            if k not in params:
                params[k] = v
        return path, params
    except Exception:
        return None, {}

def check_mod(url: str, user_store: dict) -> str:
    path, params = parse_url(url)
    if path != "/check_mod":
        return "false"
    username = params.get("username")
    password = params.get("password")
    if not is_username_valid(username):
        return "false"
    if password is None or len(password) > 128 or not is_password_valid_policy(password):
        return "false"
    rec = user_store.get(username)
    if rec is None:
        return "false"
    return "true" if verify_password(password, rec) else "false"

if __name__ == "__main__":
    store = {}
    good_user = "alice"
    good_pass = "Str0ng-P@ssw0rd!"
    store[good_user] = create_user_record(good_pass, 210_000)

    t1 = "http://localhost/check_mod?username=alice&password=Str0ng-P%40ssw0rd%21"  # true
    t2 = "/check_mod?username=alice&password=Wrong-P%40ssw0rd%21"  # false
    t3 = "/other?username=alice&password=Str0ng-P%40ssw0rd%21"  # false
    t4 = "/check_mod?username=alice"  # false
    t5 = "/check_mod?username=alice&password=short1!A"  # false

    print(check_mod(t1, store))
    print(check_mod(t2, store))
    print(check_mod(t3, store))
    print(check_mod(t4, store))
    print(check_mod(t5, store))