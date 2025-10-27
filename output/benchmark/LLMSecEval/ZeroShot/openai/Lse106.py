import os
import tempfile

def write_secret(secret: str) -> str:
    if not isinstance(secret, str):
        raise ValueError("secret must be a string")

    # Create a secure temporary file
    fd, path = tempfile.mkstemp(prefix="secret_", suffix=".txt")
    try:
        # Ensure owner read/write during write
        os.fchmod(fd, 0o600)
        data = secret.encode("utf-8")
        total = 0
        while total < len(data):
            written = os.write(fd, data[total:])
            if written <= 0:
                raise OSError("write failed")
            total += written
        os.fsync(fd)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass

    # Set to read-only for owner
    try:
        os.chmod(path, 0o400)
    except Exception:
        # Best-effort fallback for platforms without POSIX modes
        os.chmod(path, 0o444)  # read-only for all as a safe fallback

    return os.path.abspath(path)

if __name__ == "__main__":
    tests = [
        "super secret info #1",
        "super secret info #2",
        "super secret info #3",
        "super secret info #4",
        "super secret info #5",
    ]
    for s in tests:
        try:
            p = write_secret(s)
            print(p)
        except Exception as e:
            print(f"Error: {e}", flush=True)