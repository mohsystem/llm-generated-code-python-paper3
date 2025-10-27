import os
import sys
import hmac
import hashlib
import secrets
import urllib.parse
from typing import Dict, Optional

SALT_LEN = 16
HASH_LEN = 32
PBKDF2_ITERS = 210_000

class User:
    def __init__(self, username: str, salt: bytes, pw_hash: bytes, moderator: bool, session: str):
        self.username = username
        self.salt = salt
        self.pw_hash = pw_hash
        self.moderator = moderator
        self.session = session

DB: Dict[str, User] = {}

def strong_password(pw: Optional[str]) -> bool:
    if pw is None:
        return False
    if len(pw) < 12 or len(pw) > 256:
        return False
    up = any(c.isupper() for c in pw)
    lo = any(c.islower() for c in pw)
    di = any(c.isdigit() for c in pw)
    sp = any(not c.isalnum() for c in pw)
    return up and lo and di and sp

def constant_time_eq(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)

def validate_identifier(s: Optional[str], max_len: int) -> bool:
    if s is None or len(s) == 0 or len(s) > max_len:
        return False
    for ch in s:
        if not (ch.isalnum() or ch in ['_', '-', '.', '@']):
            return False
    return True

def pbkdf2_sha256(password: str, salt: bytes, iters: int, dk_len: int) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iters, dk_len)

def parse_query(url: str) -> Dict[str, str]:
    qpos = url.find('?')
    if qpos < 0:
        return {}
    query = url[qpos+1:]
    parsed = urllib.parse.parse_qs(query, strict_parsing=False, keep_blank_values=True)
    params: Dict[str, str] = {}
    for k, v in parsed.items():
        if v:
            params[k] = v[0]
    return params

def auth_mod(username: str, password: str, session: str) -> bool:
    if not validate_identifier(username, 64):
        return False
    if password is None or len(password) < 1 or len(password) > 256:
        return False
    if not validate_identifier(session, 128):
        return False
    u = DB.get(username)
    if u is None:
        return False
    if not constant_time_eq(u.session.encode('utf-8'), session.encode('utf-8')):
        return False
    derived = pbkdf2_sha256(password, u.salt, PBKDF2_ITERS, HASH_LEN)
    ok = constant_time_eq(derived, u.pw_hash)
    return ok and u.moderator

def check_mod(url: str) -> bool:
    if not url.startswith('/check_mod'):
        return False
    params = parse_query(url)
    username = params.get('username')
    password = params.get('password')
    session = params.get('session')
    if username is None or password is None or session is None:
        return False
    return auth_mod(username, password, session)

def rand_token(n: int = 16) -> str:
    return secrets.token_hex(n)

def add_user(username: str, password_env: Optional[str], moderator: bool, session_env: Optional[str]) -> None:
    if not validate_identifier(username, 64):
        return
    if password_env is None or not strong_password(password_env):
        return
    salt = secrets.token_bytes(SALT_LEN)
    pw_hash = pbkdf2_sha256(password_env, salt, PBKDF2_ITERS, HASH_LEN)
    session = session_env if (session_env and validate_identifier(session_env, 128)) else rand_token(16)
    DB[username] = User(username, salt, pw_hash, moderator, session)

def url_encode_safe(s: Optional[str]) -> str:
    if s is None:
        return ''
    return urllib.parse.quote(s, safe='-_.~')

def main() -> None:
    mod_user = os.getenv('MOD_USER', 'mod1')
    mod_pass = os.getenv('MOD_PASS')  # must be strong to be added
    mod_sess = os.getenv('MOD_SESSION')

    reg_user = os.getenv('USER_USER', 'user1')
    reg_pass = os.getenv('USER_PASS')  # must be strong to be added
    reg_sess = os.getenv('USER_SESSION')

    add_user(mod_user, mod_pass, True, mod_sess)
    add_user(reg_user, reg_pass, False, reg_sess)

    tests = []
    if mod_user in DB and mod_pass is not None:
        sess = DB[mod_user].session
        tests.append(f"/check_mod?username={mod_user}&password={url_encode_safe(mod_pass)}&session={sess}")
    else:
        tests.append(f"/check_mod?username={mod_user}&password=WrongPass123!&session=invalidsession")

    if mod_user in DB:
        sess = DB[mod_user].session
        tests.append(f"/check_mod?username={mod_user}&password=WrongPass123!&session={sess}")
    else:
        tests.append(f"/check_mod?username={mod_user}&password=WrongPass123!&session=wrong")

    if mod_user in DB and mod_pass is not None:
        tests.append(f"/check_mod?username={mod_user}&password={url_encode_safe(mod_pass)}&session=bad{rand_token(4)}")
    else:
        tests.append("/check_mod?username=nouser&password=SomethingStrong1!&session=bad")

    tests.append("/check_mod?username=ghost&password=NopePass1!&session=anything123")

    if reg_user in DB and reg_pass is not None:
        sess = DB[reg_user].session
        tests.append(f"/check_mod?username={reg_user}&password={url_encode_safe(reg_pass)}&session={sess}")
    else:
        tests.append(f"/check_mod?username={reg_user}&password=WrongPass123!&session=wrong")

    for i, t in enumerate(tests, 1):
        print(f"Test {i}: {check_mod(t)}")

if __name__ == "__main__":
    main()