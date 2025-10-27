import re
import subprocess
import sys
from typing import Optional

_INVALID_INPUT_STATUS = 2
_TIMEOUT_STATUS = 124

_USER_RE = re.compile(r'^[a-z_][a-z0-9_-]*[$]?$')

def _is_valid_username(username: Optional[str]) -> bool:
    if username is None:
        return False
    if not (1 <= len(username) <= 128):
        return False
    return _USER_RE.fullmatch(username) is not None

def run_id(username: str) -> int:
    if not _is_valid_username(username):
        return _INVALID_INPUT_STATUS
    try:
        res = subprocess.run(
            ["id", username],
            env={"PATH": "/usr/bin:/bin"},
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        return int(res.returncode)
    except subprocess.TimeoutExpired:
        return _TIMEOUT_STATUS
    except FileNotFoundError:
        return 127
    except Exception:
        return 1

if __name__ == "__main__":
    if len(sys.argv) >= 2:
        user = sys.argv[1]
        status = run_id(user)
        print(f"Exit status for username '{user}': {status}")
    else:
        tests = ["root", "nobody", "daemon", "syslog", "nonexistentuser12345"]
        for u in tests:
            status = run_id(u)
            print(f"Exit status for username '{u}': {status}")