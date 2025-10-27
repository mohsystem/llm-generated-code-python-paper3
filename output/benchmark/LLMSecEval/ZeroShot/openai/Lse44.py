import os
from pathlib import Path, PurePosixPath

MAX_SIZE_BYTES = 1024 * 1024  # 1MB
BASE_DIR = Path("/safe")

def read_safe_file(requested: str) -> str:
    if not isinstance(requested, str) or not requested:
        raise ValueError("Invalid filename")
    if "\x00" in requested:
        raise ValueError("Invalid character in filename")

    rel = PurePosixPath(requested)
    if rel.is_absolute():
        raise PermissionError("Absolute paths are not allowed")

    for part in rel.parts:
        if part in ("", ".", ".."):
            raise PermissionError("Path traversal detected")

    try:
        base_real = BASE_DIR.resolve(strict=True)
    except Exception:
        base_real = BASE_DIR.resolve()  # may not exist; subsequent checks will fail appropriately

    target = (base_real / rel).resolve(strict=True)

    try:
        target.relative_to(base_real)
    except Exception:
        raise PermissionError("Access outside of /safe is not permitted")

    # Ensure no symlinks in path components (including the final file)
    partial = base_real
    for part in target.relative_to(base_real).parts:
        partial = partial / part
        if os.path.islink(partial):
            raise PermissionError("Symlinks are not allowed")

    st = os.stat(target, follow_symlinks=False)
    if not os.path.isfile(target):
        raise PermissionError("Not a regular file")
    if st.st_size > MAX_SIZE_BYTES:
        raise PermissionError("File too large")

    fd = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        # Re-check size after opening to reduce TOCTOU risk
        st2 = os.fstat(fd)
        if st2.st_size > MAX_SIZE_BYTES:
            raise PermissionError("File too large")
        chunks = []
        remaining = MAX_SIZE_BYTES
        while True:
            to_read = 8192 if remaining >= 8192 else remaining
            if to_read <= 0:
                break
            data = os.read(fd, to_read)
            if not data:
                break
            chunks.append(data)
            remaining -= len(data)
        if remaining < 0:
            raise PermissionError("File grew beyond limit while reading")
        return b"".join(chunks).decode("utf-8", errors="replace")
    finally:
        os.close(fd)

if __name__ == "__main__":
    tests = [
        "example.txt",
        "../etc/passwd",
        "/etc/passwd",
        "subdir/file.txt",
        "symlink_outside.txt",
    ]
    for t in tests:
        try:
            content = read_safe_file(t)
            print(f"Read OK: {t} (len={len(content)})")
        except Exception as e:
            print(f"Read FAIL: {t} -> {e}")