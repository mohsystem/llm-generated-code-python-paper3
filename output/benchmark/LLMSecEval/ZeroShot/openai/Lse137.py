import hmac
import urllib.parse

MAX_VALUE_LEN = 256

_ACCOUNTS = [
    ("mod_alice", "Str0ngP@ss!", "sess-AL1CE-123"),
    ("mod_bob", "B0b$Secure", "sess-BOB-456"),
]

def _ct_equals(a: str, b: str) -> bool:
    if a is None:
        a = ""
    if b is None:
        b = ""
    # Use constant-time comparison
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))

def _parse_query(url: str):
    result = {}
    if not isinstance(url, str):
        return result
    qpos = url.find('?')
    if qpos == -1:
        return result
    path = url[:qpos]
    if path != "/check_mod":
        return result
    qs = url[qpos+1:]
    # Safe parsing and length checks
    for part in qs.split('&'):
        if not part:
            continue
        if '=' in part:
            k, v = part.split('=', 1)
        else:
            k, v = part, ""
        try:
            k = urllib.parse.unquote_plus(k, errors="strict")
            v = urllib.parse.unquote_plus(v, errors="strict")
        except Exception:
            continue
        if not k:
            continue
        if len(v) > MAX_VALUE_LEN:
            continue
        if k in ("username", "password", "session"):
            result[k] = v
    return result

def auth_mod(username: str, password: str, session: str) -> bool:
    match = 0
    for u, p, s in _ACCOUNTS:
        ueq = 1 if _ct_equals(username, u) else 0
        peq = 1 if _ct_equals(password, p) else 0
        seq = 1 if _ct_equals(session, s) else 0
        match |= (ueq & peq & seq)
    return match == 1

def check_mod(url: str) -> bool:
    if not isinstance(url, str):
        return False
    params = _parse_query(url)
    username = params.get("username")
    password = params.get("password")
    session = params.get("session")
    if username is None or password is None or session is None:
        return False
    if len(username) > MAX_VALUE_LEN or len(password) > MAX_VALUE_LEN or len(session) > MAX_VALUE_LEN:
        return False
    return auth_mod(username, password, session)

if __name__ == "__main__":
    tests = [
        "/check_mod?username=mod_alice&password=Str0ngP%40ss%21&session=sess-AL1CE-123",
        "/check_mod?username=mod_alice&password=wrong&session=sess-AL1CE-123",
        "/check_mod?username=mod_bob&password=B0b%24Secure&session=bad-session",
        "/check_mod?username=joe&password=anything&session=whatever",
        "/check_mod?username=mod_alice&password=Str0ngP%40ss%21"
    ]
    for i, t in enumerate(tests, 1):
        print(f"Test {i}: {check_mod(t)}")