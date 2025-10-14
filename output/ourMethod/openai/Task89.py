import os
import sys
import hmac
import hashlib
import secrets
from pathlib import Path
from typing import Optional, Tuple

MAGIC = b"PWD1"
VERSION = 1
SALT_LEN = 16
HASH_LEN = 32
MIN_ITERATIONS = 210_000

def resolve_safe_path(base_dir: str, rel_path: str) -> Optional[Path]:
    try:
        base = Path(base_dir).resolve(strict=False)
        target = (base / rel_path).resolve(strict=False)
        # Ensure path stays within base
        try:
            target.relative_to(base)
        except Exception:
            return None
        # Refuse symlinks when they exist
        if target.exists() and target.is_symlink():
            return None
        return target
    except Exception:
        return None

def set_owner_only_permissions(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass

def serialize_record(iterations: int, salt: bytes, hsh: bytes) -> bytes:
    return MAGIC + bytes([VERSION]) + iterations.to_bytes(4, "big") + bytes([len(salt)]) + bytes([len(hsh)]) + salt + hsh

def parse_record(data: bytes) -> Optional[Tuple[int, bytes, bytes]]:
    try:
        if len(data) < 4 + 1 + 4 + 1 + 1:
            return None
        if data[0:4] != MAGIC:
            return None
        if data[4] != VERSION:
            return None
        iterations = int.from_bytes(data[5:9], "big")
        s_len = data[9]
        h_len = data[10]
        if s_len != SALT_LEN or h_len != HASH_LEN:
            return None
        expected_len = 4 + 1 + 4 + 1 + 1 + s_len + h_len
        if len(data) != expected_len:
            return None
        salt = data[11:11+s_len]
        hsh = data[11+s_len:11+s_len+h_len]
        return (iterations, salt, hsh)
    except Exception:
        return None

def derive_key(password: str, salt: bytes, iterations: int, dklen: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, max(iterations, MIN_ITERATIONS), dklen=dklen)

def store_password(base_dir: str, rel_path: str, password: str, iterations: int) -> bool:
    if not isinstance(base_dir, str) or not isinstance(rel_path, str) or not isinstance(password, str):
        return False
    target = resolve_safe_path(base_dir, rel_path)
    if target is None:
        return False
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        return False

    salt = secrets.token_bytes(SALT_LEN)
    hsh = derive_key(password, salt, iterations, HASH_LEN)
    content = serialize_record(max(iterations, MIN_ITERATIONS), salt, hsh)

    # Atomic write
    try:
        base = Path(base_dir).resolve(strict=False)
        tmp = Path(os.path.join(str(base), f".tmp-{secrets.token_hex(8)}"))
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "wb") as f:
                try:
                    import fcntl  # type: ignore
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                except Exception:
                    pass
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
            os.replace(str(tmp), str(target))
            set_owner_only_permissions(target)
        except Exception:
            try:
                os.unlink(str(tmp))
            except Exception:
                pass
            return False
        return True
    except Exception:
        return False

def verify_password(base_dir: str, rel_path: str, password: str) -> bool:
    if not isinstance(base_dir, str) or not isinstance(rel_path, str) or not isinstance(password, str):
        return False
    target = resolve_safe_path(base_dir, rel_path)
    if target is None or not target.is_file():
        return False

    # Open safely, try to avoid following symlinks
    data = b""
    try:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(str(target), flags)
        try:
            with os.fdopen(fd, "rb") as f:
                try:
                    import fcntl  # type: ignore
                    fcntl.flock(f.fileno(), fcntl.LOCK_SH)
                except Exception:
                    pass
                data = f.read(1 << 20)
        except Exception:
            try:
                os.close(fd)
            except Exception:
                pass
            return False
    except Exception:
        return False

    parsed = parse_record(data)
    if parsed is None:
        return False
    iterations, salt, stored = parsed
    if iterations < MIN_ITERATIONS or len(salt) != SALT_LEN or len(stored) != HASH_LEN:
        return False

    computed = derive_key(password, salt, iterations, HASH_LEN)
    return hmac.compare_digest(computed, stored)

if __name__ == "__main__":
    base = "safe_store_py"
    Path(base).mkdir(parents=True, exist_ok=True)

    t1s = store_password(base, "user1.pwd", "Password#123", 210000)
    t1v = verify_password(base, "user1.pwd", "Password#123")
    print(f"Test1 (store+verify correct): {t1s and t1v}")

    t2v = verify_password(base, "user1.pwd", "WrongPassword")
    print(f"Test2 (verify incorrect): {not t2v}")

    t3v = verify_password(base, "../evil.pwd", "anything")
    print(f"Test3 (path traversal blocked): {not t3v}")

    t4v = verify_password(base, "does_not_exist.pwd", "Password#123")
    print(f"Test4 (non-existent file): {not t4v}")

    t5s = store_password(base, "user2.pwd", "Abc!2345", 300000)
    t5v = verify_password(base, "user2.pwd", "Abc!2345")
    print(f"Test5 (second user correct): {t5s and t5v}")