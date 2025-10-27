# Chain-of-Through secure implementation in Python
# 1) Problem understanding: create "important_config" with secure permissions.
# 2) Security requirements: exclusive creation, restrictive permissions (0600), validate filename.
# 3) Secure coding generation: use os.open with O_CREAT|O_EXCL and controlled umask, chmod fallback.
# 4) Code review: basename validation, safe flag usage, proper cleanup and error handling.
# 5) Secure code output: final mitigations included.

import os
import stat

def _is_valid_basename(name: str) -> bool:
    if not name:
        return False
    if os.path.isabs(name):
        return False
    # Ensure name does not include path separators or traversal
    if os.path.basename(name) != name:
        return False
    if name in (".", ".."):
        return False
    return True

def create_secure_config(filename: str) -> bool:
    if not _is_valid_basename(filename):
        return False

    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    mode = 0o600
    old_umask = None
    try:
        # Temporarily set umask to 0 to ensure exact permission creation where supported
        if hasattr(os, "umask"):
            old_umask = os.umask(0)
        fd = os.open(filename, flags, mode)
        os.close(fd)

        # Best-effort to enforce permissions (esp. on Windows where mode may be limited)
        try:
            os.chmod(filename, stat.S_IRUSR | stat.S_IWUSR)
        except Exception:
            pass
        return True
    except FileExistsError:
        return False
    except Exception:
        return False
    finally:
        if old_umask is not None:
            try:
                os.umask(old_umask)
            except Exception:
                pass

if __name__ == "__main__":
    fname = "important_config"
    for i in range(1, 6):
        try:
            os.remove(fname)
        except FileNotFoundError:
            pass
        except Exception:
            pass
        result = create_secure_config(fname)
        print(f"Test {i} create_secure_config('{fname}') -> {result}")