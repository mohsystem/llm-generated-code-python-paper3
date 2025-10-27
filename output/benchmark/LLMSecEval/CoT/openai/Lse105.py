# Chain-of-Through:
# 1) Problem: Create/overwrite secret.txt with given content; set restrictive perms.
# 2) Security: Create with restrictive perms atomically; avoid broad perms window.
# 3) Generation: Use os.open with mode 0o600; write; chmod to enforce.
# 4) Review: Handles errors; uses UTF-8; cross-platform best-effort.
# 5) Output: Returns True/False.

import os

def create_secret_file(filename: str, content: str) -> bool:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    mode = 0o600  # owner read/write only
    fd = None
    try:
        fd = os.open(filename, flags, mode)
        with os.fdopen(fd, 'w', encoding='utf-8', newline='') as f:
            fd = None  # fd is owned by file object now
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        # Ensure restrictive perms (re-apply)
        try:
            os.chmod(filename, mode)
        except Exception:
            pass
        return True
    except Exception:
        if fd is not None:
            try:
                os.close(fd)
            except Exception:
                pass
        return False

if __name__ == "__main__":
    filename = "secret.txt"
    content = "U2FsdGVkX1/R+WzJcxgvX/Iw=="
    for i in range(1, 6):
        print(f"Test {i}: {create_secret_file(filename, content)}")