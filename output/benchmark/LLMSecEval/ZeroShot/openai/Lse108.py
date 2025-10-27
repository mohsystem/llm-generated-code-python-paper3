import os
import re
import tempfile
import sys

def _is_valid_username(username: str) -> bool:
    if not isinstance(username, str):
        return False
    if not (1 <= len(username) <= 32):
        return False
    # Must start with alphanumeric or underscore; remaining can be alnum, underscore, dot, or dash
    return re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}', username) is not None

def get_user_info_system(username: str, output) -> int:
    """
    Execute 'getent passwd <username>' via os.system and redirect output to the given file object.
    Returns the system() exit status.
    """
    if not _is_valid_username(username):
        return 400  # invalid input
    if output is None:
        return 400
    try:
        fd = output.fileno()
    except Exception:
        return 400

    try:
        output.flush()
    except Exception:
        return 400

    # Use absolute path for getent; redirect stdout and stderr to the provided fd.
    cmd = f"/usr/bin/getent passwd {username} 1>&{fd} 2>&1"
    # Optionally constrain PATH for safety
    os.putenv("PATH", "/usr/bin:/bin")
    return os.system(cmd)

def _read_all(f):
    try:
        f.seek(0)
        return f.read()
    except Exception:
        return ""

def main():
    tests = ["root", "nobody", "daemon", "thisuserdoesnotexist12345", "bin"]
    for t in tests:
        with tempfile.TemporaryFile(mode='w+') as f:
            rc = get_user_info_system(t, f)
            content = _read_all(f)
            sys.stdout.write(f"=== Python Test for '{t}' (rc={rc}) ===\n")
            sys.stdout.write(content if content else "(no output)\n")

if __name__ == "__main__":
    main()