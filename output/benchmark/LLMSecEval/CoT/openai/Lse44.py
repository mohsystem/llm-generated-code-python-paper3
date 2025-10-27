# Step 1: Problem understanding: securely read a requested file from /safe
# Step 2: Security requirements: prevent traversal, enforce base, avoid symlink escapes, limit size
# Step 3/5: Secure coding and output

from pathlib import Path

MAX_BYTES = 5 * 1024 * 1024  # 5 MiB

def read_safe_file(requested_path: str, max_bytes: int = MAX_BYTES) -> str:
    if requested_path is None:
        raise ValueError("requested_path cannot be None")

    base = Path("/safe").resolve()

    rp = requested_path.replace("\\", "/")
    rp = rp.lstrip("/")

    target = (base / rp)

    # Resolve the path strictly to eliminate symlinks and get canonical path
    target_real = target.resolve(strict=True)

    # Ensure the resolved path is inside base
    if base not in target_real.parents:
        raise PermissionError("Access denied: target escapes base directory")

    if not target_real.is_file():
        raise OSError("Not a regular file")

    size = target_real.stat().st_size
    if size > max_bytes:
        raise OSError("File too large")

    data = target_real.read_bytes()
    if len(data) > max_bytes:
        raise OSError("File too large")

    # Decode as UTF-8; replace invalid sequences to avoid decode errors during demo
    return data.decode("utf-8", errors="replace")


if __name__ == "__main__":
    # Step 4: Code review done, run 5 test cases
    tests = [
        "example.txt",
        "subdir/data.txt",
        "../etc/passwd",
        "/safe/../safe/secret.txt",
        "nonexistent.txt",
    ]
    for t in tests:
        print(f"=== Test: {t} ===")
        try:
            content = read_safe_file(t)
            print(f"Read OK. Length: {len(content)}")
        except Exception as e:
            print(f"Error: {type(e).__name__} - {e}")