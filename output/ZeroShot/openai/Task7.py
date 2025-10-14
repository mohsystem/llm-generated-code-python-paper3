import os
import sys
import hmac
import hashlib
import secrets
import urllib.parse

def build_login_request(username: str, password: str) -> str:
    if not isinstance(username, str) or not isinstance(password, str):
        return ""
    u = username.strip()
    if not u or len(u) > 128 or len(password) == 0 or len(password) > 256:
        return ""
    ue = urllib.parse.quote(u, safe="")
    pe = urllib.parse.quote(password, safe="")
    return f"u={ue}&p={pe}"

def process_request(request: str, user_db_path: str) -> str:
    try:
        if not request:
            return "ERR: Malformed request"
        qs = dict(x.split("=", 1) for x in request.split("&") if "=" in x)
        if "u" not in qs or "p" not in qs:
            return "ERR: Malformed request"
        username = urllib.parse.unquote(qs["u"])
        password = urllib.parse.unquote(qs["p"])
        if not username or not password:
            return "ERR: Missing credentials"
        rec = lookup_user(user_db_path, username)
        if rec is None:
            return "ERR: Invalid credentials"
        salt, iterations, stored = rec["salt"], rec["iterations"], rec["hash"]
        derived = kdf(password.encode("utf-8"), salt, iterations)
        ok = hmac.compare_digest(derived, stored)
        return "OK" if ok else "ERR: Invalid credentials"
    except Exception:
        return "ERR: Server error"

def lookup_user(path: str, username: str):
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(":")
                if len(parts) != 4:
                    continue
                if parts[0] != username:
                    continue
                try:
                    it = int(parts[1])
                except ValueError:
                    continue
                salt = bytes.fromhex(parts[2])
                hsh = bytes.fromhex(parts[3])
                return {"salt": salt, "iterations": it, "hash": hsh}
    except Exception:
        return None
    return None

def create_user_db(path: str, users: dict, iterations: int = 100000) -> None:
    try:
        with open(path, "w", encoding="utf-8") as f:
            for username, password in users.items():
                if not username or not password:
                    continue
                salt = secrets.token_bytes(16)
                h = kdf(password.encode("utf-8"), salt, iterations)
                f.write(f"{username}:{iterations}:{salt.hex()}:{h.hex()}\n")
        try:
            if hasattr(os, "chmod"):
                os.chmod(path, 0o600)
        except Exception:
            pass
    finally:
        # Clear sensitive data best-effort
        for k in list(users.keys()):
            users[k] = ""

def kdf(password: bytes, salt: bytes, iterations: int) -> bytes:
    # Iterated salted SHA-256: H = SHA256(salt || password); repeat hashing
    if iterations < 1:
        iterations = 1
    h = hashlib.sha256(salt + password).digest()
    for _ in range(iterations - 1):
        h = hashlib.sha256(h).digest()
    return h

def main():
    db_path = "userdb_py.txt"
    users = {
        "alice": "Password123!",
        "bob": "S3cur3Pa$$",
        "charlie": "letmein",
    }
    create_user_db(db_path, users, iterations=100000)

    tests = [
        ("alice", "Password123!"),
        ("alice", "wrong"),
        ("dave", "doesntmatter"),
        ("bob", ""),
        ("bob", "S3cur3Pa$$"),
    ]
    for i, (u, p) in enumerate(tests, 1):
        req = build_login_request(u, p)
        resp = process_request(req, db_path)
        print(f"Test {i} -> {resp}")

    try:
        os.remove(db_path)
    except Exception:
        pass

if __name__ == "__main__":
    main()