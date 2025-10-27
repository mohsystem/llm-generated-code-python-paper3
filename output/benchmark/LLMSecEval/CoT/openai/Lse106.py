import os
import stat
import tempfile
import uuid

def write_secret_to_readonly_file(secret: str, filename: str | None = None) -> str:
    if secret is None:
        raise ValueError("secret cannot be None")

    path = None
    if filename and filename.strip():
        path = os.path.abspath(filename)
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        # Create new file with 0600 permissions
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        mode = 0o600
        fd = os.open(path, flags, mode)
    else:
        fd, path = tempfile.mkstemp(prefix="secret_", suffix=".txt")
        # mkstemp sets mode 0600 already

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(secret)
            f.flush()
            try:
                os.fsync(f.fileno())
            except Exception:
                pass
    finally:
        try:
            os.close(fd)
        except Exception:
            pass

    # Set read-only for owner
    try:
        if os.name == "nt":
            os.chmod(path, stat.S_IREAD)
        else:
            os.chmod(path, 0o400)
    except Exception:
        # Best-effort fallback on platforms without POSIX perms
        try:
            os.chmod(path, stat.S_IREAD)
        except Exception:
            pass

    return path

if __name__ == "__main__":
    # 5 test cases
    secrets = [
        f"TopSecret-Alpha-{uuid.uuid4()}",
        f"TopSecret-Bravo-{uuid.uuid4()}",
        f"TopSecret-Charlie-{uuid.uuid4()}",
        f"TopSecret-Delta-{uuid.uuid4()}",
        f"TopSecret-Echo-{uuid.uuid4()}",
    ]

    # Test 1: auto temp
    p1 = write_secret_to_readonly_file(secrets[0], None)
    print(p1)

    # Test 2: specified file unique
    specified2 = os.path.join(tempfile.gettempdir(), f"secret_spec_{uuid.uuid4()}.txt")
    p2 = write_secret_to_readonly_file(secrets[1], specified2)
    print(p2)

    # Test 3: auto temp
    p3 = write_secret_to_readonly_file(secrets[2], "")
    print(p3)

    # Test 4: specified nested path
    nested_dir = os.path.join(tempfile.gettempdir(), f"secdir_{uuid.uuid4()}")
    specified4 = os.path.join(nested_dir, f"secret_{uuid.uuid4()}.txt")
    p4 = write_secret_to_readonly_file(secrets[3], specified4)
    print(p4)

    # Test 5: auto temp
    p5 = write_secret_to_readonly_file(secrets[4], None)
    print(p5)