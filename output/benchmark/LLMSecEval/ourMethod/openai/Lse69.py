import os
import stat
import base64
import tempfile
import re
from typing import Optional

MAX_SIZE = 8 * 1024 * 1024  # 8 MiB
SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]{1,255}$")


def _is_safe_filename(name: str) -> bool:
    if not isinstance(name, str):
        return False
    if len(name) == 0 or len(name) > 255:
        return False
    if name in (".", ".."):
        return False
    if "/" in name or "\\" in name:
        return False
    return SAFE_NAME.match(name) is not None


def upload_image(base_dir: str, input_name: str, output_name: str) -> Optional[str]:
    # Validate inputs
    if not isinstance(base_dir, str) or not _is_safe_filename(input_name) or not _is_safe_filename(output_name):
        return None

    try:
        os.makedirs(base_dir, exist_ok=True)
        # Try to set restrictive permissions on the base_dir (best effort)
        try:
            os.chmod(base_dir, 0o700)
        except Exception:
            pass

        input_path = os.path.join(base_dir, input_name)
        # Open input safely (best-effort no-follow)
        flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        fd = None
        try:
            fd = os.open(input_path, flags | nofollow, dir_fd=None, follow_symlinks=False)
        except TypeError:
            # Older Python: retry without follow_symlinks kwarg
            fd = os.open(input_path, flags | nofollow)
        except FileNotFoundError:
            return None
        except Exception:
            return None

        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                return None
            if st.st_size < 0 or st.st_size > MAX_SIZE:
                return None

            with os.fdopen(fd, "rb", closefd=True) as f:
                data = f.read(MAX_SIZE + 1)
        except Exception:
            try:
                os.close(fd)
            except Exception:
                pass
            return None

        if data is None:
            return None

        # Base64 encode
        b64 = base64.b64encode(data)

        # Write to temp file in base_dir with restrictive perms and atomic rename
        try:
            tmp_fd, tmp_path = tempfile.mkstemp(prefix="enc-", suffix=".tmp", dir=base_dir)
            try:
                os.fchmod(tmp_fd, 0o600)
            except Exception:
                pass
            with os.fdopen(tmp_fd, "wb", closefd=True) as tf:
                tf.write(b64)
                tf.flush()
                os.fsync(tf.fileno())
        except Exception:
            # Ensure tmp is cleaned if partially created
            try:
                if 'tmp_fd' in locals():
                    os.close(tmp_fd)
            except Exception:
                pass
            try:
                if 'tmp_path' in locals():
                    os.unlink(tmp_path)
            except Exception:
                pass
            return None

        dest_path = os.path.join(base_dir, output_name)
        # Avoid overwrite; os.rename fails if dest exists on POSIX
        try:
            os.rename(tmp_path, dest_path)
        except FileExistsError:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
            return None
        except Exception:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
            return None

        # fsync directory best-effort
        try:
            dir_fd = os.open(base_dir, os.O_DIRECTORY | os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except Exception:
            pass

        try:
            os.chmod(dest_path, 0o600)
        except Exception:
            pass

        return os.path.abspath(dest_path)
    except Exception:
        return None


def _write_sample_file(base_dir: str, name: str, content: bytes) -> None:
    if not _is_safe_filename(name):
        raise ValueError("invalid name")
    path = os.path.join(base_dir, name)
    fd, tmp = tempfile.mkstemp(prefix="in-", suffix=".tmp", dir=base_dir)
    with os.fdopen(fd, "wb", closefd=True) as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())
    try:
        os.rename(tmp, path)
    except OSError:
        os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass


def main():
    base = os.path.abspath("base_py")
    os.makedirs(base, exist_ok=True)

    # Create 5 sample files
    contents = [
        bytes([0x89, 0x50, 0x4E, 0x47]) + os.urandom(28),
        b"\xFF\xD8\xFF" + os.urandom(61),
        b"GIF89a" + os.urandom(122),
        os.urandom(16),
        b"BM" + os.urandom(254),
    ]
    names = ["img1.bin", "img2.jpg", "img3.png", "icon4.gif", "photo5.bmp"]
    for n, c in zip(names, contents):
        _write_sample_file(base, n, c)

    outs = ["img1.b64", "img2.b64", "img3.b64", "icon4.b64", "photo5.b64"]
    for inp, outp in zip(names, outs):
        res = upload_image(base, inp, outp)
        if res:
            print("OK:", res)
        else:
            print("FAIL")


if __name__ == "__main__":
    main()