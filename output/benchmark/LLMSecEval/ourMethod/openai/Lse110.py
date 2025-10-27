import re
import subprocess
import sys
from typing import List

# Validate username: length 1..32, ASCII only, starts with [A-Za-z_],
# then [A-Za-z0-9_.-], optional trailing '$'
_USERNAME_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_.-]{0,30}\$?$')

def is_valid_username(u: str) -> bool:
    if not isinstance(u, str):
        return False
    if len(u) < 1 or len(u) > 32:
        return False
    try:
        u.encode('ascii')
    except UnicodeEncodeError:
        return False
    return bool(_USERNAME_RE.fullmatch(u))

def run_id_command(username: str) -> int:
    if not is_valid_username(username):
        print("Invalid username.", file=sys.stderr)
        return 2  # invalid input
    try:
        cp = subprocess.run(["id", username], check=False)
        return cp.returncode
    except PermissionError:
        return 126  # permission problem
    except FileNotFoundError:
        return 127  # command not found
    except Exception:
        return 127  # generic execution error

def main() -> None:
    if len(sys.argv) >= 2:
        username = sys.argv[1]
        status = run_id_command(username)
        print(f"Exit status: {status}")
        return
    # 5 test cases
    tests: List[str] = ["root", "daemon", "nobody", "bin", "this_user_should_not_exist_zzz"]
    for t in tests:
        print(f"Running: id {t}")
        status = run_id_command(t)
        print(f"Exit status: {status}")

if __name__ == "__main__":
    main()