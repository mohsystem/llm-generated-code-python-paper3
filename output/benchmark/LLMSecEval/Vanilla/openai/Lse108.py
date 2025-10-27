import os
import sys

def _shell_quote(s):
    return "'" + s.replace("'", "'\"'\"'") + "'"

def getent_to_file(username, output):
    if not hasattr(output, "fileno"):
        return -1
    try:
        output.flush()
    except Exception:
        pass
    try:
        saved_fd = os.dup(1)
    except OSError:
        return -1
    try:
        os.dup2(output.fileno(), 1)
        cmd = "getent passwd " + _shell_quote(username)
        status = os.system(cmd)
        sys.stdout.flush()
    finally:
        try:
            os.dup2(saved_fd, 1)
        finally:
            os.close(saved_fd)
    return status

if __name__ == "__main__":
    tests = [
        ("root", "py_out1.txt"),
        ("nobody", "py_out2.txt"),
        ("daemon", "py_out3.txt"),
        (os.environ.get("USER") or "root", "py_out4.txt"),
        ("no_such_user_xyz_12345", "py_out5.txt"),
    ]
    for user, path in tests:
        with open(path, "w") as f:
            getent_to_file(user, f)