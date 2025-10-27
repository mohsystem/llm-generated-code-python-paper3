import os
import re
import shlex
import sys
import tempfile
from typing import IO

USER_RE = re.compile(r"^[A-Za-z0-9._-]{1,32}$")

def getent_to_fp(username: str, output: IO) -> int:
    """
    Execute 'getent passwd <username>' using os.system and direct stdout to the given file object.
    Returns the process exit code (0 if found).
    """
    if not isinstance(username, str) or not USER_RE.fullmatch(username):
        return -1
    if not hasattr(output, "fileno"):
        return -1
    try:
        fd = output.fileno()
    except Exception:
        return -1

    # Preserve inheritable flag and ensure the FD is inherited by the child shell.
    try:
        prev_inh = os.get_inheritable(fd)
    except AttributeError:
        # Fallback if not available; assume False then set True below
        prev_inh = False
    os.set_inheritable(fd, True)
    try:
        # Use shell-safe quoting for the username (defense-in-depth)
        safe_user = shlex.quote(username)
        # Redirect stdout to the provided file descriptor; silence stderr.
        cmd = f"getent passwd {safe_user} 1>&{fd} 2>/dev/null"
        rc = os.system(cmd)
        # Normalize to exit code
        try:
            exit_code = os.waitstatus_to_exitcode(rc)  # Python 3.9+
        except AttributeError:
            exit_code = (rc >> 8) & 0xFF
        return exit_code
    finally:
        try:
            os.set_inheritable(fd, prev_inh)
        except Exception:
            pass

def _run_tests():
    tests = ["root", "nobody", "daemon", "thisuserdoesnotexist", "bad;injection"]
    for u in tests:
        with tempfile.TemporaryFile(mode="w+b") as f:
            rc = getent_to_fp(u, f)
            f.flush()
            f.seek(0)
            data = f.read().decode("utf-8", errors="replace")
            print(f"User: {u} -> rc={rc}")
            if data:
                sys.stdout.write(data)
            else:
                print("(no output)")
            print("----")

if __name__ == "__main__":
    _run_tests()