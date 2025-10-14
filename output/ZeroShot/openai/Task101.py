import os
import uuid
import tempfile

def create_executable_script(dir_path: str, content: str, overwrite: bool):
    default_content = '#!/bin/sh\necho "Hello from script.sh"\n'
    data = content if content else default_content
    if not data.endswith("\n"):
        data += "\n"

    try:
        base = dir_path if dir_path and isinstance(dir_path, str) and len(dir_path) > 0 else "."
        base = os.path.abspath(base)
        os.makedirs(base, exist_ok=True)

        final_path = os.path.abspath(os.path.join(base, "script.sh"))

        # Ensure final_path resides in base directory to mitigate path traversal
        if os.path.dirname(final_path) != base:
            return None

        if not overwrite and os.path.lexists(final_path):
            return None

        tmp_path = os.path.join(base, f"script.sh.tmp-{uuid.uuid4().hex}")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        mode = 0o700  # owner rwx
        fd = os.open(tmp_path, flags, mode)
        try:
            b = data.encode("utf-8")
            total = 0
            while total < len(b):
                written = os.write(fd, b[total:])
                if written <= 0:
                    raise OSError("Write failed")
                total += written
            os.fsync(fd)
        finally:
            os.close(fd)

        # Ensure permissions (best-effort)
        try:
            os.chmod(tmp_path, 0o700)
        except Exception:
            pass

        # Atomic replace/move
        try:
            os.replace(tmp_path, final_path)
        except Exception:
            # Cleanup tmp if replace failed
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
            return None

        # Final permissions (best-effort)
        try:
            os.chmod(final_path, 0o700)
        except Exception:
            pass

        # Confirm it's not a symlink
        if os.path.islink(final_path):
            try:
                os.unlink(final_path)
            except Exception:
                pass
            return None

        return final_path
    except Exception:
        return None

if __name__ == "__main__":
    # 5 test cases
    d1 = tempfile.mkdtemp(prefix="t101_py_1_")
    d2 = tempfile.mkdtemp(prefix="t101_py_2_")

    r1 = create_executable_script(d1, "#!/bin/sh\necho Case1", False)
    print("Test1:", r1)

    r2 = create_executable_script(d1, "#!/bin/sh\necho Case2", False)  # should fail (exists)
    print("Test2:", r2)

    r3 = create_executable_script(d1, "#!/bin/sh\necho Case3 Overwrite", True)  # overwrite
    print("Test3:", r3)

    r4 = create_executable_script(d2, "echo Case4 Content only", False)
    print("Test4:", r4)

    r5 = create_executable_script(".", "echo Case5 in CWD", True)
    print("Test5:", r5)