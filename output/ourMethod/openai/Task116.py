import os
import sys
import pwd
import grp
import secrets
import hashlib
from typing import Tuple, Dict

# In-memory store to simulate password updates (not the OS password DB)
HASH_STORE: Dict[str, str] = {}

def validate_username(username: str) -> bool:
    if username is None:
        return False
    if len(username) < 1 or len(username) > 32:
        return False
    for c in username:
        if not (c.isalnum() or c in "_-"):
            return False
    return True

def validate_password(password: str) -> bool:
    if password is None:
        return False
    if len(password) < 12 or len(password) > 128:
        return False
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    specials = set("!@#$%^&*()-_=+[]{}|;:',.<>/?`~\"\\")
    has_special = any(c in specials for c in password)
    return has_upper and has_lower and has_digit and has_special

def get_current_ids(dummy: int) -> Tuple[int, int]:
    uid = os.getuid() if hasattr(os, "getuid") else -1
    euid = os.geteuid() if hasattr(os, "geteuid") else uid
    return uid, euid

def is_root_from_euid(euid: int) -> bool:
    return euid == 0

def pbkdf2_hash(password: str, salt: bytes, iterations: int = 120_000, dklen: int = 32) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=dklen)
    return "pbkdf2_sha256$%d$%s$%s" % (iterations, salt.hex(), dk.hex())

def perform_privileged_password_change(current_euid: int, username: str, new_password: str) -> bool:
    if not is_root_from_euid(current_euid):
        return False
    if not validate_username(username):
        return False
    if not validate_password(new_password):
        return False
    salt = secrets.token_bytes(16)
    hashed = pbkdf2_hash(new_password, salt)
    HASH_STORE[username] = hashed
    return True

def drop_privileges(current_euid: int, target_user: str) -> bool:
    if not is_root_from_euid(current_euid):
        return False
    if not target_user or len(target_user) > 32:
        return False
    try:
        pw_record = pwd.getpwnam(target_user)
        target_uid = pw_record.pw_uid
        target_gid = pw_record.pw_gid
        # Set supplementary groups, then gid, then uid
        os.initgroups(pw_record.pw_name, target_gid)
        os.setgid(target_gid)
        os.setuid(target_uid)
        # Verify drop: cannot regain root
        try:
            os.setuid(0)  # should fail
            return False
        except PermissionError:
            pass
        return os.geteuid() != 0 and os.getuid() != 0
    except KeyError:
        return False
    except Exception:
        return False

def change_password_then_drop(username: str, new_password: str, target_user: str) -> Tuple[bool, bool]:
    _, euid = get_current_ids(0)
    changed = perform_privileged_password_change(euid, username, new_password)
    dropped = False
    if changed:
        dropped = drop_privileges(euid, target_user)
    return changed, dropped

def can_still_perform_privileged_ops(dummy: int) -> bool:
    _, euid = get_current_ids(dummy)
    return is_root_from_euid(euid)

def main() -> None:
    tests = [
        ("alice", "StrongPassw0rd!", "nobody"),
        ("bob-01", "Another$trongP4ss", "daemon"),
        ("bad!name", "ValidP@ssw0rd2025", "nobody"),
        ("charlie", "WeakPass1!", "nobody"),
        ("d", "Too$hort1", "nobody"),
    ]
    for i, (u, p, t) in enumerate(tests, 1):
        # reset in-memory store per test for clarity
        HASH_STORE.clear()
        changed, dropped = change_password_then_drop(u, p, t)
        can_priv = can_still_perform_privileged_ops(0)
        print(f"Test{i}: changedAndDropped={changed and dropped}, canPrivNow={can_priv}, storedUsers={list(HASH_STORE.keys())}")

if __name__ == "__main__":
    main()