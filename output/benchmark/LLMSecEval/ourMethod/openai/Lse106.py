import os
import stat
import tempfile
import secrets

def _validate_filename(name: str) -> None:
    if not isinstance(name, str) or len(name) == 0 or len(name) > 255:
        raise OSError("Invalid filename length")
    if "/" in name or "\\" in name or name in (".", ".."):
        raise OSError("Invalid filename path components")
    for ch in name:
        if not (ch.isalnum() or ch in "._-"):
            raise OSError("Invalid filename characters")

def write_secret_file(base_dir: str, filename: str) -> str:
    _validate_filename(filename)

    # Create secret string (do not print it)
    secret = "TOP-SECRET: Highly confidential data. Do not disclose."

    # Open base directory securely
    dirfd = None
    tmpfd = None
    tmpname = None
    try:
        dirfd = os.open(base_dir, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0))
        st = os.fstat(dirfd)
        if not stat.S_ISDIR(st.st_mode):
            raise OSError("Base is not a directory")

        # Create a unique temp file name
        tmpname = ".tmp_" + secrets.token_hex(12) + ".part"

        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_CLOEXEC", 0)
        # O_NOFOLLOW is best effort; may not be available on some platforms
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW

        # Create the temp file in the base directory with 0600 perms
        tmpfd = os.open(tmpname, flags, 0o600, dir_fd=dirfd)
        fst = os.fstat(tmpfd)
        if not stat.S_ISREG(fst.st_mode):
            raise OSError("Not a regular file")

        # Write the secret
        data = secret.encode("utf-8")
        total = 0
        while total < len(data):
            n = os.write(tmpfd, data[total:])
            if n <= 0:
                raise OSError("Short write")
            total += n

        # Flush file content to disk
        os.fsync(tmpfd)

        # Set file to owner read-only before rename
        os.fchmod(tmpfd, 0o400)

        # Atomically rename into place within the same directory
        os.rename(tmpname, filename, src_dir_fd=dirfd, dst_dir_fd=dirfd)

        # Fsync directory to persist rename
        os.fsync(dirfd)

        return os.path.join(base_dir, filename)
    finally:
        # Cleanup temp file if it still exists
        try:
            if dirfd is not None and tmpname is not None:
                try:
                    # Attempt unlink in case rename failed
                    os.unlink(tmpname, dir_fd=dirfd)
                except FileNotFoundError:
                    pass
                except Exception:
                    pass
        except Exception:
            pass
        if tmpfd is not None:
            try:
                os.close(tmpfd)
            except Exception:
                pass
        if dirfd is not None:
            try:
                os.close(dirfd)
            except Exception:
                pass

if __name__ == "__main__":
    try:
        base = tempfile.mkdtemp(prefix="safe_base_")
        names = ["secret1.txt", "secret2.txt", "alpha-3.log", "note_4.dat", "report5"]
        for n in names:
            path = write_secret_file(base, n)
            print(path)
    except Exception:
        print("Operation failed")