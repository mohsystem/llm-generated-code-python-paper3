import os
import re
import secrets
from typing import Optional

MAX_SIZE = 1 * 1024 * 1024  # 1 MiB


def _sanitize_error(msg: Optional[str]) -> str:
    if not msg:
        return "Operation failed."
    msg = msg.replace("\r", " ").replace("\n", " ")
    return msg[:200]


def _is_safe_filename(name: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9._-]{1,128}", name)) and name not in {".", ".."}


def upload_file(base_dir: str, file_name: str, data: bytes) -> str:
    try:
        # Validate inputs
        if not isinstance(base_dir, str) or not base_dir.strip():
            return "ERROR: Base directory is required."
        if not isinstance(file_name, str) or not _is_safe_filename(file_name):
            return "ERROR: Invalid file name."
        if not isinstance(data, (bytes, bytearray)) or len(data) == 0:
            return "ERROR: No data provided."
        if len(data) > MAX_SIZE:
            return "ERROR: File too large."

        # Prepare base directory securely
        base = os.path.abspath(base_dir)
        os.makedirs(base, exist_ok=True)

        # Reject symlink base
        try:
            if os.path.islink(base):
                return "ERROR: Base directory cannot be a symlink."
        except OSError:
            return "ERROR: Unable to verify base directory."

        base_real = os.path.realpath(base)

        # Resolve target path and ensure it stays within base
        target = os.path.normpath(os.path.join(base_real, file_name))
        if os.path.dirname(target) != base_real:
            return "ERROR: Invalid path resolution."

        # Reject if existing target is a symlink
        try:
            if os.path.lexists(target) and os.path.islink(target):
                return "ERROR: Target path is an unsafe symlink."
        except OSError:
            return "ERROR: Unable to verify target path."

        # Create a unique temp file in base
        tmp_name = f"{file_name}.tmp.{secrets.token_hex(16)}"
        temp = os.path.join(base_real, tmp_name)

        # Ensure temp does not exist
        if os.path.exists(temp):
            return "ERROR: Temporary file collision."

        # Write to temp with restrictive permissions and fsync
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            total = 0
            # Write in chunks for safety
            mv = memoryview(data)
            chunk = 8192
            while total < len(data):
                w = os.write(fd, mv[total: total + chunk])
                if w <= 0:
                    raise OSError("Short write")
                total += w
            os.fsync(fd)
        finally:
            os.close(fd)

        # Move to final destination atomically if supported; avoid overwriting
        if os.path.exists(target):
            try:
                os.remove(temp)
            except OSError:
                pass
            return "ERROR: File already exists."
        try:
            os.replace(temp, target)  # typically atomic
        except OSError as e:
            try:
                os.remove(temp)
            except OSError:
                pass
            return f"ERROR: {_sanitize_error(str(e))}"

        # Final check: must be a regular file, not symlink
        try:
            st = os.lstat(target)
            if not os.path.isfile(target) or os.path.islink(target):
                try:
                    os.remove(target)
                except OSError:
                    pass
                return "ERROR: Target is not a regular file."
        except OSError:
            return "ERROR: Unable to stat target file."

        return f"OK: Stored file '{file_name}' ({len(data)} bytes)."
    except Exception as ex:
        return f"ERROR: {_sanitize_error(str(ex))}"


if __name__ == "__main__":
    import tempfile

    base = tempfile.mkdtemp(prefix="task50_py_base_")

    # Test 1: Valid upload
    print(upload_file(base, "file1.txt", b"Hello, world!"))

    # Test 2: Another valid upload
    print(upload_file(base, "safe_name.bin", b"Some binary \x00 content"))

    # Test 3: Invalid name (path traversal attempt)
    print(upload_file(base, "bad/../name.txt", b"x"))

    # Test 4: Duplicate upload should fail
    print(upload_file(base, "file1.txt", b"new content"))

    # Test 5: Oversize upload
    print(upload_file(base, "big.bin", b"a" * (MAX_SIZE + 1)))