import os

# Step 1-2: Implement functionality and apply secure defaults.
def secure_write(filename: str, content: str) -> bool:
    if not isinstance(filename, str) or not isinstance(content, str):
        return False
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    try:
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
    except Exception:
        pass
    mode = 0o600
    try:
        # Step 3: Open/create with restrictive permissions.
        fd = os.open(filename, flags, mode)
        try:
            # Step 4: Ensure restrictive permissions on existing file (best-effort).
            try:
                os.chmod(filename, mode)
            except Exception:
                pass
            # Step 5: Write content safely.
            with os.fdopen(fd, "w", encoding="utf-8", closefd=True) as f:
                f.write(content)
                f.flush()
                try:
                    os.fsync(f.fileno())
                except Exception:
                    pass
        except Exception:
            try:
                os.close(fd)
            except Exception:
                pass
            return False
        return True
    except OSError:
        return False

if __name__ == "__main__":
    print(secure_write("important_config", "important_config"))
    print(secure_write("important_config", "important_config"))
    print(secure_write("./important_config", "important_config"))
    print(secure_write("important_config", "important_config"))
    print(secure_write("important_config", "important_config"))