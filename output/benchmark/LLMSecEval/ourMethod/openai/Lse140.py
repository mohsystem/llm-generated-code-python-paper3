import os
import re
import tempfile
from typing import Optional


def _is_valid_username(username: Optional[str]) -> bool:
    if not isinstance(username, str):
        return False
    if len(username) < 1 or len(username) > 64:
        return False
    # Allowed: A-Z a-z 0-9 _ . -
    return re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', username) is not None


def _is_safe_path(p: Optional[str]) -> bool:
    if not isinstance(p, str):
        return False
    if len(p) < 1 or len(p) > 4096:
        return False
    if ".." in p:
        return False
    return True


def username_exists(db_path: str, username: str) -> bool:
    if not _is_valid_username(username):
        return False
    if not _is_safe_path(db_path):
        return False

    try:
        if not os.path.isfile(db_path):
            return False
        # Avoid following symlinks
        if os.path.islink(db_path):
            return False

        with open(db_path, "r", encoding="utf-8", errors="strict") as f:
            for line in f:
                if len(line) > 256:
                    # Skip unusually long lines
                    continue
                record = line.rstrip("\n\r")
                if _is_valid_username(record) and record == username:
                    return True
        return False
    except Exception:
        # Fail closed
        return False


def _create_sample_db() -> str:
    tf = tempfile.NamedTemporaryFile(prefix="users_", suffix=".db", delete=False, mode="w", encoding="utf-8", newline="\n")
    try:
        tf.write("alice\n")
        tf.write("Bob_123\n")
        tf.write("charlie\n")
        tf.write("david.s\n")
        tf.write("eve-9\n")
        tf.flush()
        os.fchmod(tf.fileno(), 0o600)
        return tf.name
    finally:
        tf.close()


if __name__ == "__main__":
    db_path = _create_sample_db()
    try:
        tests = [
            "alice",    # True
            "bob_123",  # False (case-sensitive)
            "charlie",  # True
            "mallory",  # False
            "eve-9"     # True
        ]
        for t in tests:
            print(f"{t} -> {username_exists(db_path, t)}")
    finally:
        try:
            os.remove(db_path)
        except Exception:
            pass