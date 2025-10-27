import os
import sys
import errno
import secrets
import string

MAX_PDF_SIZE = 10 * 1024 * 1024  # 10 MiB

def _sanitize_filename(name: str) -> str:
    # drop path components
    base = name.rsplit('/', 1)[-1].rsplit('\\', 1)[-1]
    allowed = set(string.ascii_lowercase + string.digits + "._-")
    out = []
    for ch in base.lower()[:128]:
        out.append(ch if ch in allowed else '_')
    if not out:
        out = list("upload.pdf")
    res = "".join(out)
    if not res.endswith(".pdf"):
        while res.endswith("."):
            res = res[:-1]
        res += ".pdf"
    while ".." in res:
        res = res.replace("..", ".")
    if res.startswith("."):
        res = "u" + res
    return res

def save_pdf(data: bytes, original_filename: str, base_dir: str) -> str:
    if not isinstance(data, (bytes, bytearray)) or not isinstance(original_filename, str) or not isinstance(base_dir, str):
        raise OSError("invalid input")
    if len(data) < 5 or len(data) > MAX_PDF_SIZE:
        raise OSError("invalid size")
    if data[:5] != b"%PDF-":
        raise OSError("invalid pdf header")

    sanitized = _sanitize_filename(original_filename)
    if not sanitized.endswith(".pdf"):
        raise OSError("invalid extension")

    # Open base directory safely (avoid symlinks where possible)
    dflags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        dflags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        dflags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        dflags |= os.O_NOFOLLOW

    try:
        dfd = os.open(base_dir, dflags)
    except OSError as e:
        raise OSError("base directory invalid") from e

    try:
        st = os.fstat(dfd)
        if not stat_is_dir(st.st_mode):
            raise OSError("base directory invalid")

        # Create a unique temp file within base directory
        tmpname = "upload_" + secrets.token_hex(16) + ".tmp"
        fflags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_CLOEXEC"):
            fflags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            fflags |= os.O_NOFOLLOW

        try:
            fd = os.openat(dfd, tmpname, fflags, 0o600)
        except OSError as e:
            if e.errno == errno.ELOOP:
                raise OSError("symlink refused")
            raise

        try:
            stf = os.fstat(fd)
            if not stat_is_reg(stf.st_mode):
                raise OSError("not a regular file")

            # Write bytes safely
            total = 0
            mv = memoryview(data)
            while total < len(data):
                n = os.write(fd, mv[total:])
                if n <= 0:
                    raise OSError("write failed")
                total += n
                if total > MAX_PDF_SIZE:
                    raise OSError("size exceeded")

            os.fsync(fd)
        finally:
            os.close(fd)

        # Atomically create destination name by hard-linking temp into final name
        # Ensures no overwrite and no symlink following
        try:
            os.link(tmpname, sanitized, src_dir_fd=dfd, dst_dir_fd=dfd, follow_symlinks=False)
        except FileExistsError:
            raise OSError("destination exists")
        finally:
            # Remove the temp name regardless of link success to avoid leaks
            try:
                os.unlink(tmpname, dir_fd=dfd)
            except OSError:
                pass

        # Fsync the directory to ensure directory entry is on disk
        try:
            os.fsync(dfd)
        except OSError:
            pass

        # Return absolute path
        return os.path.abspath(os.path.join(base_dir, sanitized))
    finally:
        os.close(dfd)

def stat_is_dir(mode: int) -> bool:
    return (mode & 0o170000) == 0o040000

def stat_is_reg(mode: int) -> bool:
    return (mode & 0o170000) == 0o100000

def _make_uploads():
    try:
        os.makedirs("uploads", mode=0o700, exist_ok=True)
    except Exception:
        pass

def main():
    _make_uploads()

    # Test 1: Valid PDF
    try:
        path1 = save_pdf(b"%PDF-1.7\n...", "report.pdf", "uploads")
        print("OK1:", path1)
    except Exception:
        print("FAIL1")

    # Test 2: Path traversal attempt
    try:
        path2 = save_pdf(b"%PDF-1.7\n...", "../../evil.pdf", "uploads")
        print("OK2:", path2)
    except Exception:
        print("FAIL2")

    # Test 3: Wrong extension
    try:
        path3 = save_pdf(b"%PDF-1.7\n...", "image.png", "uploads")
        print("OK3:", path3)
    except Exception:
        print("FAIL3")

    # Test 4: Too big
    big = bytearray(MAX_PDF_SIZE + 1)
    big[:5] = b"%PDF-"
    try:
        path4 = save_pdf(big, "big.pdf", "uploads")
        print("OK4:", path4)
    except Exception:
        print("FAIL4")

    # Test 5: Odd characters filename
    try:
        path5 = save_pdf(b"%PDF-1.4\n...", "a..//b??.pdf", "uploads")
        print("OK5:", path5)
    except Exception:
        print("FAIL5")

if __name__ == "__main__":
    main()