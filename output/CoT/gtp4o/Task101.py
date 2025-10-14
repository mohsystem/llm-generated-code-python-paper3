import os
import errno
import tempfile
import stat

# Step 1: Problem understanding:
# Create "script.sh" in a given directory, write provided content, and make it executable.

# Step 2: Security requirements:
# - Do not overwrite existing files (O_EXCL).
# - Avoid following symlinks (O_NOFOLLOW if available).
# - Minimal required permissions (700 if executable else 600).
# - fsync to ensure content durability.

# Step 3: Secure coding generation:
def create_script_file(directory: str, content: str, set_executable: bool = True) -> bool:
    if not directory:
        return False
    if content is None:
        content = ""
    directory = os.path.abspath(directory)
    target = os.path.join(directory, "script.sh")

    try:
        os.makedirs(directory, exist_ok=True)
    except Exception:
        return False

    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    mode = 0o700 if set_executable else 0o600

    fd = -1
    try:
        fd = os.open(target, flags, mode)
        data = content.encode("utf-8")
        total = 0
        while total < len(data):
            written = os.write(fd, data[total:])
            if written <= 0:
                raise OSError("Short write")
            total += written
        try:
            os.fsync(fd)
        except Exception:
            pass
        # Ensure executable if requested (in case umask reduced mode)
        if set_executable:
            try:
                st = os.fstat(fd)
                os.fchmod(fd, (st.st_mode | stat.S_IXUSR) & 0o777)
            except Exception:
                # Fallback to chmod by path
                try:
                    os.chmod(target, 0o700)
                except Exception:
                    return False
        return True
    except FileExistsError:
        return False
    except OSError as e:
        # If O_NOFOLLOW unsupported path or other errors
        return False
    finally:
        if fd != -1:
            try:
                os.close(fd)
            except Exception:
                pass

# Step 4 and 5: Code review & Secure code output: Applied above.

if __name__ == "__main__":
    for i in range(1, 6):
        tmpdir = tempfile.mkdtemp(prefix=f"task101_py_test_{i}_")
        content = f"#!/bin/sh\necho 'Hello from Python test {i}'\n"
        ok = create_script_file(tmpdir, content, True)
        script_path = os.path.join(tmpdir, "script.sh")
        print(f"Test {i} dir: {tmpdir}")
        print(f"  Created: {ok}")
        print(f"  Exists: {os.path.exists(script_path)}")
        try:
            exec_ok = os.access(script_path, os.X_OK)
        except Exception:
            exec_ok = False
        print(f"  Executable: {exec_ok}")