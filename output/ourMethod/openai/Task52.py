import os
import sys
import secrets
import stat
from pathlib import Path
from typing import Tuple
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b'ENC1'
VERSION = b'\x01'
SALT_LEN = 16
IV_LEN = 12
PBKDF2_ITERS = 210_000
KEY_LEN = 32

def _resolve_safe_path(base_dir: Path, rel: str, for_write: bool) -> Path:
    if rel is None:
        raise ValueError("Null path")
    base = base_dir.resolve(strict=False)
    if not base.exists() or not base.is_dir():
        raise ValueError("Base invalid")
    rel_path = Path(rel)
    if rel_path.is_absolute():
        raise ValueError("Absolute path not allowed")
    cand = (base / rel_path).resolve(strict=False)
    try:
        # Ensure path stays within base using pure path comparison
        cand_abs = cand.resolve(strict=False)
    except Exception:
        cand_abs = cand
    if not str(cand_abs).startswith(str(base) + os.sep) and cand_abs != base:
        raise ValueError("Path escapes base")
    # Reject symlinks in components
    _reject_symlinks_in_path(base, cand.parent if for_write else cand)
    if not for_write:
        if not cand.exists() or not cand.is_file():
            raise ValueError("Input not a regular file")
    else:
        if cand.exists() and cand.is_symlink():
            raise ValueError("Output is symlink")
        parent = cand.parent
        if not parent.exists() or not parent.is_dir():
            raise ValueError("Parent invalid")
    return cand

def _reject_symlinks_in_path(base: Path, target: Path) -> None:
    base = base.resolve(strict=False)
    try:
        target_abs = target.resolve(strict=False)
    except Exception:
        target_abs = target
    if not str(target_abs).startswith(str(base) + os.sep) and target_abs != base:
        raise ValueError("Path escapes base")
    cur = base
    rel = target_abs.relative_to(base)
    for part in rel.parts:
        cur = cur / part
        try:
            st = os.lstat(cur)
            if stat.S_ISLNK(st.st_mode):
                raise ValueError("Symlink encountered")
        except FileNotFoundError:
            # Non-existent final is ok for write
            break

def _derive_key(passphrase: str, salt: bytes) -> bytes:
    if not isinstance(passphrase, str) or len(passphrase) == 0:
        raise ValueError("Invalid passphrase")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=KEY_LEN, salt=salt, iterations=PBKDF2_ITERS)
    key = kdf.derive(passphrase.encode('utf-8'))
    return key

def _atomic_write(path: Path, data_iter):
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    tmp_name = f".tmp_{os.getpid()}_{secrets.token_hex(6)}"
    tmp_path = parent / tmp_name
    fd = None
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(str(tmp_path), flags, 0o600)
        with os.fdopen(fd, "wb", buffering=0) as f:
            fd = None
            for chunk in data_iter:
                f.write(chunk)
            f.flush()
            os.fsync(f.fileno())
        os.replace(str(tmp_path), str(path))
        try:
            os.chmod(str(path), 0o600)
        except Exception:
            pass
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except Exception:
                pass
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except Exception:
                pass

def encrypt_file(base_dir: str, input_rel: str, output_rel: str, passphrase: str) -> bool:
    try:
        base = Path(base_dir)
        in_path = _resolve_safe_path(base, input_rel, for_write=False)
        out_path = _resolve_safe_path(base, output_rel, for_write=True)
        salt = secrets.token_bytes(SALT_LEN)
        iv = secrets.token_bytes(IV_LEN)
        key = _derive_key(passphrase, salt)
        aesgcm = AESGCM(key)
        with open(in_path, "rb") as f:
            plaintext = f.read()
        ct = aesgcm.encrypt(iv, plaintext, None)  # ciphertext + tag
        header = MAGIC + VERSION + salt + iv
        def chunks():
            yield header
            yield ct
        _atomic_write(out_path, chunks())
        return True
    except Exception:
        return False

def decrypt_file(base_dir: str, input_rel: str, output_rel: str, passphrase: str) -> bool:
    try:
        base = Path(base_dir)
        in_path = _resolve_safe_path(base, input_rel, for_write=False)
        out_path = _resolve_safe_path(base, output_rel, for_write=True)
        with open(in_path, "rb") as f:
            data = f.read()
        if len(data) < len(MAGIC) + 1 + SALT_LEN + IV_LEN + 16:
            return False
        if data[:4] != MAGIC or data[4:5] != VERSION:
            return False
        salt = data[5:5+SALT_LEN]
        iv = data[5+SALT_LEN:5+SALT_LEN+IV_LEN]
        ct = data[5+SALT_LEN+IV_LEN:]
        key = _derive_key(passphrase, salt)
        aesgcm = AESGCM(key)
        try:
            pt = aesgcm.decrypt(iv, ct, None)
        except Exception:
            return False
        def chunks():
            yield pt
        _atomic_write(out_path, chunks())
        return True
    except Exception:
        return False

def _write_file(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())

def main():
    from tempfile import mkdtemp
    base = Path(mkdtemp(prefix="enc_base_py_"))
    passphrase = "StrongPassphrase!123"

    contents = [
        b"",
        b"Hello, World!",
        "こんにちは世界🌏".encode("utf-8"),
        secrets.token_bytes(1024),
        secrets.token_bytes(128 * 1024),
    ]

    overall = True
    for i, data in enumerate(contents):
        in_rel = f"input_{i}.bin"
        enc_rel = f"out_{i}.enc"
        dec_rel = f"dec_{i}.bin"
        _write_file(base / in_rel, data)
        ok1 = encrypt_file(str(base), in_rel, enc_rel, passphrase)
        ok2 = decrypt_file(str(base), enc_rel, dec_rel, passphrase)
        match = False
        try:
            with open(base / dec_rel, "rb") as f:
                dec = f.read()
            match = (dec == data)
        except Exception:
            match = False
        print(f"Test {i} => encrypt: {ok1}, decrypt: {ok2}, match: {match}")
        overall = overall and ok1 and ok2 and match
    print(f"Overall: {'SUCCESS' if overall else 'FAIL'}")

if __name__ == "__main__":
    main()