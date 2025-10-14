import os
import stat
import sys
import uuid
from typing import Optional


def create_executable_script(base_dir: str, content: str) -> bool:
    if not isinstance(base_dir, str) or not isinstance(content, str):
        return False
    if len(base_dir) == 0 or len(base_dir) > 4096:
        return False

    try:
        # Normalize and create base directory if needed
        base_dir = os.path.abspath(base_dir)
        if not os.path.exists(base_dir):
            # Secure directory creation with mode 0700 (on POSIX)
            os.makedirs(base_dir, mode=0o700, exist_ok=False)
        # Refuse if base_dir is a symlink or not a directory
        st = os.lstat(base_dir)
        if stat.S_ISLNK(st.st_mode):
            return False
        if not stat.S_ISDIR(st.st_mode):
            return False

        # Tighten permissions where possible
        try:
            os.chmod(base_dir, 0o700)
        except PermissionError:
            pass

        final_path = os.path.join(base_dir, "script.sh")

        # Fail closed if target exists (no overwrite)
        try:
            st_final = os.lstat(final_path)
            return False
        except FileNotFoundError:
            pass

        # Create temp file securely in same directory
        temp_path = os.path.join(base_dir, f".script.sh.tmp-{uuid.uuid4().hex}")
        fd: Optional[int] = None
        try:
            fd = os.open(temp_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            data = content.encode("utf-8")
            total = 0
            while total < len(data):
                written = os.write(fd, data[total:])
                if written <= 0:
                    raise OSError("short write")
                total += written
            os.fsync(fd)
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass

        # Set temp file permissions to 0700 (owner rwx)
        try:
            os.chmod(temp_path, 0o700)
        except PermissionError:
            pass

        # Atomic publish without overwrite:
        # Prefer hard link + unlink which fails if final exists
        published = False
        try:
            os.link(temp_path, final_path)
            os.unlink(temp_path)
            published = True
        except (OSError, NotImplementedError):
            # Fallback to rename within same directory (atomic on most filesystems).
            # Will fail if final exists on Windows; on POSIX it may overwrite, so we pre-check existence above.
            try:
                os.rename(temp_path, final_path)
                published = True
            finally:
                if not published:
                    try:
                        os.unlink(temp_path)
                    except OSError:
                        pass

        if not published:
            return False

        # Ensure final is executable by owner only
        try:
            os.chmod(final_path, 0o700)
        except PermissionError:
            pass

        return True
    except Exception:
        return False


def _tmp_base(suffix: str) -> str:
    return os.path.join(os.path.abspath(os.getenv("TMPDIR") or os.getenv("TEMP") or "/tmp"), f"Task101_{suffix}")


def main() -> None:
    content = "#!/bin/sh\necho \"Hello from script\"\n"

    # Test 1: Valid base dir
    t1 = _tmp_base("test1")
    print("Test1:", create_executable_script(t1, content))

    # Test 2: Non-existing nested dir
    t2 = os.path.join(_tmp_base("test2"), "nested")
    print("Test2:", create_executable_script(t2, content))

    # Test 3: Path normalization
    base3a = os.path.join(_tmp_base("test3"), "a")
    t3 = os.path.join(base3a, "..", "b")
    print("Test3:", create_executable_script(t3, content))

    # Test 4: Pre-existing script.sh
    t4 = _tmp_base("test4")
    try:
        os.makedirs(t4, exist_ok=True)
        pre = os.path.join(t4, "script.sh")
        if not os.path.exists(pre):
            with open(pre, "w", encoding="utf-8") as f:
                f.write("#!/bin/sh\necho preexisting\n")
    except Exception:
        pass
    print("Test4 (exists):", create_executable_script(t4, content))

    # Test 5: Base path is a file
    t5file = _tmp_base("test5_as_file")
    try:
        with open(t5file, "w", encoding="utf-8") as f:
            f.write("not a dir")
    except Exception:
        pass
    print("Test5 (base is file):", create_executable_script(t5file, content))


if __name__ == "__main__":
    main()