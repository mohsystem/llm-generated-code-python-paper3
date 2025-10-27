from typing import Dict

DB: Dict[str, str] = {
    "alice": "Wonderland!42",
    "bob": "Secure*Pass9",
    "charlie": "S3cret#Key",
}

_DUMMY_PASSWORD = "dummy_secret_password_123"

def _is_printable_ascii(s: str) -> bool:
    return all(32 <= ord(ch) <= 126 for ch in s)

def _constant_time_equals(a: bytes, b: bytes) -> bool:
    max_len = max(len(a), len(b))
    diff = len(a) ^ len(b)
    for i in range(max_len):
        ba = a[i] if i < len(a) else 0
        bb = b[i] if i < len(b) else 0
        diff |= (ba ^ bb)
    return diff == 0

def login(username: str, password: str) -> str:
    try:
        if username is None or password is None:
            return "internal_server_error"
        if not (1 <= len(username) <= 128 and 1 <= len(password) <= 128):
            return "internal_server_error"
        if not _is_printable_ascii(username) or not _is_printable_ascii(password):
            return "internal_server_error"

        stored = DB.get(username)
        compare_against = stored if stored is not None else _DUMMY_PASSWORD

        match = _constant_time_equals(password.encode("utf-8"), compare_against.encode("utf-8"))
        if stored is not None and match:
            return "success"
        else:
            return "cant_login"
    except Exception:
        return "internal_server_error"

if __name__ == "__main__":
    # 5 test cases
    print(login("alice", "Wonderland!42"))  # success
    print(login("bob", "Secure*Pass9"))     # success
    print(login("alice", "NotIt"))          # cant_login
    print(login("dave", "anything"))        # cant_login
    print(login(None, "x"))                 # internal_server_error