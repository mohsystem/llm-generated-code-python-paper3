import os
import stat

def _mode_to_symbolic(mode: int) -> str:
    # Build a symbolic string like -rw------- from st_mode
    perms = ['-']
    # Owner
    perms.append('r' if (mode & stat.S_IRUSR) else '-')
    perms.append('w' if (mode & stat.S_IWUSR) else '-')
    perms.append('x' if (mode & stat.S_IXUSR) else '-')
    # Group
    perms.append('r' if (mode & stat.S_IRGRP) else '-')
    perms.append('w' if (mode & stat.S_IWGRP) else '-')
    perms.append('x' if (mode & stat.S_IXGRP) else '-')
    # Others
    perms.append('r' if (mode & stat.S_IROTH) else '-')
    perms.append('w' if (mode & stat.S_IWOTH) else '-')
    perms.append('x' if (mode & stat.S_IXOTH) else '-')
    return ''.join(perms)

def create_and_restrict(path: str, data: str) -> str:
    p = os.fspath(path)
    try:
        # Refuse to operate on symlink
        if os.path.lexists(p) and os.path.islink(p):
            raise OSError(f"Refusing to operate on symlink: {p}")

        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        cloexec = getattr(os, "O_CLOEXEC", 0)
        flags |= nofollow | cloexec

        # Create and open with restrictive mode; umask may restrict further which is fine
        fd = os.open(p, flags, 0o600)
        try:
            os.write(fd, data.encode('utf-8'))
            try:
                os.fsync(fd)
            except Exception:
                pass
        finally:
            os.close(fd)

        # Explicitly chmod to 600
        try:
            os.chmod(p, 0o600)
        except Exception:
            # On non-POSIX, this may be best-effort
            pass

        st = os.lstat(p)
        perm_str = _mode_to_symbolic(st.st_mode)
        print(perm_str)
        return perm_str
    except Exception as e:
        msg = f"ERROR: {e}"
        print(msg)
        return msg

if __name__ == "__main__":
    secret = "U2FsdGVkX1/R+WzJcxgvX/Iw=="
    create_and_restrict("secret.txt", secret)
    create_and_restrict("secret1.txt", secret)
    create_and_restrict("secret2.txt", secret)
    create_and_restrict("secret3.txt", secret)
    create_and_restrict("secret4.txt", secret)