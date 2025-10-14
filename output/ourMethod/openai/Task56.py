import base64
import hmac
import hashlib
import secrets
import struct
import time
from typing import Optional

MAGIC = b"TKN1"
VERSION = 1
NONCE_LEN = 16
TAG_LEN = 32
MAX_USER_LEN = 1024
MIN_KEY_LEN = 16
MIN_TTL = 1
MAX_TTL = 604800  # 7 days

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _b64url_decode(s: str) -> Optional[bytes]:
    try:
        pad = "=" * ((4 - (len(s) % 4)) % 4)
        return base64.urlsafe_b64decode(s + pad)
    except Exception:
        return None

def generate_token(user_id: str, key: bytes, ttl_seconds: int) -> str:
    if not isinstance(user_id, str):
        raise ValueError("user_id must be str")
    user_bytes = user_id.encode("utf-8")
    if len(user_bytes) == 0 or len(user_bytes) > MAX_USER_LEN:
        raise ValueError("user_id length invalid")
    if not isinstance(key, (bytes, bytearray)) or len(key) < MIN_KEY_LEN:
        raise ValueError("key invalid")
    if not (MIN_TTL <= ttl_seconds <= MAX_TTL):
        raise ValueError("ttl out of range")

    now = int(time.time())
    nonce = secrets.token_bytes(NONCE_LEN)

    header = MAGIC + bytes([VERSION])
    body = struct.pack("!Q", now) + struct.pack("!I", ttl_seconds) + nonce + struct.pack("!H", len(user_bytes)) + user_bytes
    to_mac = header + body
    tag = hmac.new(key, to_mac, hashlib.sha256).digest()
    token_bytes = to_mac + tag
    return _b64url_encode(token_bytes)

def verify_token(token: str, key: bytes, expected_user_id: str, now_epoch: Optional[int] = None) -> bool:
    if not isinstance(token, str) or not isinstance(key, (bytes, bytearray)) or not isinstance(expected_user_id, str):
        return False
    if len(key) < MIN_KEY_LEN:
        return False

    raw = _b64url_decode(token)
    if raw is None:
        return False

    min_len = len(MAGIC) + 1 + 8 + 4 + NONCE_LEN + 2 + TAG_LEN
    if len(raw) < min_len:
        return False

    off = 0
    magic = raw[off:off+4]; off += 4
    if magic != MAGIC:
        return False
    ver = raw[off]; off += 1
    if ver != VERSION:
        return False
    if off + 8 + 4 + NONCE_LEN + 2 > len(raw) - TAG_LEN:
        return False

    ts = struct.unpack("!Q", raw[off:off+8])[0]; off += 8
    ttl = struct.unpack("!I", raw[off:off+4])[0]; off += 4
    if not (MIN_TTL <= ttl <= MAX_TTL):
        return False
    nonce = raw[off:off+NONCE_LEN]; off += NONCE_LEN
    user_len = struct.unpack("!H", raw[off:off+2])[0]; off += 2
    if user_len < 1 or user_len > MAX_USER_LEN:
        return False
    if off + user_len != len(raw) - TAG_LEN:
        return False
    user_bytes = raw[off:off+user_len]; off += user_len
    tag = raw[off:off+TAG_LEN]

    to_mac = raw[:len(raw)-TAG_LEN]
    exp_tag = hmac.new(key, to_mac, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, exp_tag):
        return False

    expected_user_bytes = expected_user_id.encode("utf-8")
    if not hmac.compare_digest(user_bytes, expected_user_bytes):
        return False

    now = int(now_epoch if now_epoch is not None else time.time())
    if now > ts + ttl:
        return False

    return True

def _tamper_token(token: str) -> str:
    if not token:
        return token
    alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    last = token[-1]
    if last not in alpha:
        return token[:-1] + alpha[0]
    return token[:-1] + (alpha[1] if last == alpha[0] else alpha[0])

def main() -> None:
    key = secrets.token_bytes(32)
    users = ["alice", "bob", "carol", "dave_123", "eve@example.com"]

    # Test 1: valid token
    t1 = generate_token(users[0], key, 600)
    r1 = verify_token(t1, key, users[0], int(time.time()))
    print("Test1 valid:", r1)

    # Test 2: expired
    t2 = generate_token(users[1], key, 1)
    r2 = verify_token(t2, key, users[1], int(time.time()) + 5000)
    print("Test2 expired:", not r2)

    # Test 3: wrong user
    t3 = generate_token(users[2], key, 600)
    r3 = verify_token(t3, key, users[0], int(time.time()))
    print("Test3 wrong user:", not r3)

    # Test 4: tampered token
    t4 = generate_token(users[3], key, 600)
    t4_bad = _tamper_token(t4)
    r4 = verify_token(t4_bad, key, users[3], int(time.time()))
    print("Test4 tampered:", not r4)

    # Test 5: wrong key
    wrong_key = secrets.token_bytes(32)
    t5 = generate_token(users[4], key, 600)
    r5 = verify_token(t5, wrong_key, users[4], int(time.time()))
    print("Test5 wrong key:", not r5)

if __name__ == "__main__":
    main()