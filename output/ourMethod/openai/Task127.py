import os
import sys
import errno
import tempfile
from pathlib import Path
from typing import Optional

def _safe_msg(e: Exception) -> str:
    m = str(e)
    return (m.replace("\r", " ").replace("\n", " ").replace("\t", " ")).strip() or e.__class__.__name__

def _is_or_has_symlink(target: Path, stop_at_inclusive: Path) -> bool:
    try:
        target_abs = target.resolve(strict=False).absolute()
        stop_abs = stop_at_inclusive.resolve(strict=False).absolute()
    except Exception:
        return True
    # Check each component from target to stop
    p = target_abs
    while True:
        try:
            if p.is_symlink():
                return True
        except Exception:
            return True
        if p == stop_abs or p.parent == p:
            break
        p = p.parent
    return False

def copy_to_temp(base_dir: str, user_relative_path: str, temp_dir: str) -> str:
    # Validate inputs
    if base_dir is None or user_relative_path is None or temp_dir is None:
        return "ERROR: Null input parameter"
    base_dir = base_dir.strip()
    user_relative_path = user_relative_path.strip()
    temp_dir = temp_dir.strip()
    if not base_dir or not user_relative_path or not temp_dir:
        return "ERROR: Empty input parameter"
    if len(user_relative_path) > 4096:
        return "ERROR: Path too long"
    if "\x00" in user_relative_path:
        return "ERROR: Invalid character in path"

    base = Path(base_dir).absolute().resolve(strict=False)
    tmpd = Path(temp_dir).absolute().resolve(strict=False)

    try:
        if not base.exists():
            return "ERROR: Base directory does not exist"
        if not base.is_dir():
            return "ERROR: Base path is not a directory"
        if _is_or_has_symlink(base, base):
            return "ERROR: Base directory or its parents contain a symlink"

        user_p = Path(user_relative_path)
        if user_p.is_absolute():
            return "ERROR: Path must be relative to base directory"

        resolved = (base / user_p).resolve(strict=False)
        # Ensure resolved path stays within base by lexical normalization
        if not str(resolved.absolute()).startswith(str(base.absolute()) + os.sep) and resolved != base:
            return "ERROR: Path escapes base directory"

        if _is_or_has_symlink(resolved, base):
            return "ERROR: Source path contains a symlink"
        if not resolved.exists():
            return "ERROR: Source file does not exist"
        if not resolved.is_file():
            return "ERROR: Source is not a regular file"

        # Ensure temp directory exists
        try:
            tmpd.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            return "ERROR: Cannot create temp directory: " + _safe_msg(e)
        if not tmpd.is_dir():
            return "ERROR: Temp path is not a directory"
        if _is_or_has_symlink(tmpd, tmpd):
            return "ERROR: Temp directory or its parents contain a symlink"

        # Create temp file securely
        try:
            tf = tempfile.NamedTemporaryFile(prefix="copy_", suffix=".tmp", dir=str(tmpd), delete=False)
            temp_path = Path(tf.name)
            # Restrictive permissions: 0o600
            try:
                os.chmod(str(temp_path), 0o600)
            except Exception:
                pass
        except Exception as e:
            return "ERROR: Cannot create temp file: " + _safe_msg(e)

        # Open source safely. Use O_NOFOLLOW if available (POSIX).
        src_fd: Optional[int] = None
        try:
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            src_fd = os.open(str(resolved), flags)
        except Exception as e:
            try:
                tf.close()
                os.unlink(tf.name)
            except Exception:
                pass
            return "ERROR: Cannot open source file: " + _safe_msg(e)

        # Optional: lock the source file on POSIX
        try:
            if sys.platform != "win32":
                import fcntl  # type: ignore
                fcntl.flock(src_fd, fcntl.LOCK_SH)
        except Exception:
            # If locking fails, proceed but we already mitigate by copying to temp
            pass

        # Copy data
        try:
            with os.fdopen(src_fd, "rb", closefd=True) as src, tf:
                # Acquire an exclusive lock on destination where supported
                try:
                    if sys.platform != "win32":
                        import fcntl  # type: ignore
                        fcntl.flock(tf.fileno(), fcntl.LOCK_EX)
                except Exception:
                    pass
                while True:
                    chunk = src.read(8192)
                    if not chunk:
                        break
                    tf.write(chunk)
                tf.flush()
                os.fsync(tf.fileno())
        except Exception as e:
            try:
                os.unlink(temp_path)
            except Exception:
                pass
            return "ERROR: I/O error during copy: " + _safe_msg(e)

        return str(temp_path.resolve())

    except Exception as e:
        return "ERROR: " + _safe_msg(e)


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)

def main() -> None:
    # Setup test environment
    base = Path(tempfile.mkdtemp(prefix="base_dir_"))
    temp_out = Path(tempfile.mkdtemp(prefix="temp_out_"))
    f1 = base / "file1.txt"
    _write_text(f1, "Hello world 1")
    sub = base / "subdir"
    sub.mkdir(parents=True, exist_ok=True)
    f2 = sub / "file2.txt"
    _write_text(f2, "Hello world 2")
    # Attempt to create a symlink if possible
    try:
        link = base / "link_to_f1"
        if link.exists() or link.is_symlink():
            link.unlink()
        os.symlink("file1.txt", str(link))
    except Exception:
        pass

    # Five test cases
    print("Test1:", copy_to_temp(str(base), "file1.txt", str(temp_out)))
    print("Test2:", copy_to_temp(str(base), "subdir/file2.txt", str(temp_out)))
    print("Test3:", copy_to_temp(str(base), "../../etc/passwd", str(temp_out)))
    print("Test4:", copy_to_temp(str(base), "does_not_exist.txt", str(temp_out)))
    print("Test5:", copy_to_temp(str(base), str(f1.resolve()), str(temp_out)))

if __name__ == "__main__":
    main()