import hmac
import hashlib
import re
from urllib.parse import urlparse, parse_qs

SALT = "u$er-salt::"
EXPECTED_USERNAME = "admin"
EXPECTED_PASSWORD = "s3cureP@ss"
MAX_USERNAME_LEN = 64
MAX_PASSWORD_LEN = 256

_username_re = re.compile(r'^[A-Za-z0-9._-]{1,64}$')

def _is_valid_username(u: str) -> bool:
    if u is None:
        return False
    return _username_re.match(u) is not None

def check_mod(url: str) -> str:
    if url is None:
        return "false"
    p = urlparse(url)
    path = p.path or ""
    if path != "/check_mod":
        return "false"
    qs = parse_qs(p.query, keep_blank_values=True, strict_parsing=False)
    username = qs.get("username", [""])[0]
    password = qs.get("password", [""])[0]
    if not _is_valid_username(username):
        return "false"
    if not (1 <= len(password) <= MAX_PASSWORD_LEN):
        return "false"

    # Constant-time compare username
    if not hmac.compare_digest(username.encode(), EXPECTED_USERNAME.encode()):
        return "false"

    expected_hash = hashlib.sha256((SALT + EXPECTED_PASSWORD).encode()).digest()
    provided_hash = hashlib.sha256((SALT + password).encode()).digest()
    if not hmac.compare_digest(expected_hash, provided_hash):
        return "false"

    return "true"

if __name__ == "__main__":
    tests = [
        "/check_mod?username=admin&password=s3cureP%40ss",
        "/check_mod?username=admin&password=wrong",
        "/check_mod?username=Admin&password=s3cureP%40ss",
        "/check_mod?username=admin",
        "/other?username=admin&password=s3cureP%40ss",
    ]
    for t in tests:
        print(check_mod(t))