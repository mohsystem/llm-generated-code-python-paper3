import os
import re
import tempfile

# Secure helper: validate username to prevent command injection
def _is_valid_username(username: str) -> bool:
    if not isinstance(username, str):
        return False
    # Allow only typical username characters and limit length
    return bool(re.fullmatch(r'[A-Za-z0-9._-]{1,32}', username))

# Core function: executes "getent passwd <username>" using system() and writes output to provided file object
def get_user_info_to_output(username: str, output) -> str:
    if not _is_valid_username(username):
        return ""
    if not hasattr(output, "fileno"):
        return ""
    try:
        fd = output.fileno()
    except Exception:
        return ""
    try:
        # Record current position if seekable
        pos_before = None
        try:
            pos_before = output.tell()
        except Exception:
            pos_before = None

        output.flush()
        # Build safe command; username validated to avoid injection.
        cmd = f"getent passwd {username} 1>&{fd} 2>&{fd}"
        # Execute via system()
        rc = os.system(cmd)
        if rc == -1:
            return ""

        try:
            output.flush()
        except Exception:
            pass

        # Attempt to read back just-written data if the stream is seekable
        if pos_before is not None:
            try:
                output.seek(0, os.SEEK_END)
                end_pos = output.tell()
                if end_pos >= pos_before:
                    output.seek(pos_before, os.SEEK_SET)
                    data = output.read(end_pos - pos_before)
                    # Return as text if bytes
                    if isinstance(data, bytes):
                        return data.decode(errors="replace")
                    return data if data is not None else ""
            except Exception:
                return ""
        return ""
    except Exception:
        return ""

# Test harness with 5 test cases
def _run_tests():
    tests = ["root", "nobody", "daemon", "doesnotexistuser", "root;echo HACKED"]
    for t in tests:
        with tempfile.TemporaryFile(mode="w+b") as f:
            result = get_user_info_to_output(t, f)
            print(f"Test username='{t}' -> Output: {result.strip()}")

if __name__ == "__main__":
    _run_tests()