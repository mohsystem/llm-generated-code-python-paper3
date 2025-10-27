import os
import hmac
import hashlib
import secrets
from typing import Dict, Tuple

# UserRecord: username -> (salt_bytes, hash_bytes)
UserRecord = Tuple[bytes, bytes]

def create_user_record(username: str, password: str) -> UserRecord:
    if username is None or password is None:
        raise ValueError("Invalid input")
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100_000, dklen=32)
    return (salt, dk)

def authenticate_and_redirect(db: Dict[str, UserRecord], username: str, password: str) -> str:
    if not db or username is None or password is None:
        return "redirect:/login"
    rec = db.get(username)
    if rec is None:
        return "redirect:/login"
    salt, stored = rec
    computed = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100_000, dklen=32)
    if hmac.compare_digest(stored, computed):
        return "redirect:/dashboard"
    return "redirect:/login"

def main():
    db: Dict[str, UserRecord] = {}
    db["alice"] = create_user_record("alice", "S3curePass!")
    db["bob"] = create_user_record("bob", "hunter2?")

    print(authenticate_and_redirect(db, "alice", "S3curePass!"))  # dashboard
    print(authenticate_and_redirect(db, "alice", "wrongpass"))    # login
    print(authenticate_and_redirect(db, "unknown", "anything"))   # login
    print(authenticate_and_redirect(db, "bob", "hunter2?"))       # dashboard
    print(authenticate_and_redirect(db, "", ""))                  # login

if __name__ == "__main__":
    main()