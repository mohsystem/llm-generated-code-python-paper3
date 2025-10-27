import os
import stat

def _mode_to_perm_string(mode: int) -> str:
    # Build rwxrwxrwx
    perms = []
    perms.append('r' if mode & stat.S_IRUSR else '-')
    perms.append('w' if mode & stat.S_IWUSR else '-')
    perms.append('x' if mode & stat.S_IXUSR else '-')
    perms.append('r' if mode & stat.S_IRGRP else '-')
    perms.append('w' if mode & stat.S_IWGRP else '-')
    perms.append('x' if mode & stat.S_IXGRP else '-')
    perms.append('r' if mode & stat.S_IROTH else '-')
    perms.append('w' if mode & stat.S_IWOTH else '-')
    perms.append('x' if mode & stat.S_IXOTH else '-')
    return ''.join(perms)

def secure_write_restrict_print(path: str, content: str) -> str:
    # Create/overwrite with controlled flags; then enforce 0600 regardless of umask
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    mode = 0o600
    fd = None
    try:
        fd = os.open(path, flags, mode)
        with os.fdopen(fd, 'w', encoding='utf-8', closefd=True) as f:
            fd = None
            f.write(content)
        os.chmod(path, 0o600)
        st = os.stat(path)
        eff_mode = stat.S_IMODE(st.st_mode)
        perm_str = _mode_to_perm_string(eff_mode)
        return f"{eff_mode:04o} {perm_str}"
    except Exception as e:
        return f"ERROR: {e}"
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except Exception:
                pass

if __name__ == "__main__":
    content = "U2FsdGVkX1/R+WzJcxgvX/Iw=="
    path = "secret.txt"
    print(secure_write_restrict_print(path, content))
    print(secure_write_restrict_print(path, content))
    print(secure_write_restrict_print(path, content))
    print(secure_write_restrict_print(path, content))
    print(secure_write_restrict_print(path, content))