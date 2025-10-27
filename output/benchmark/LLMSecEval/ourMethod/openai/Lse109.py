import re
import subprocess
import sys
from typing import List

USERNAME_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_-]{0,31}$')

def get_user_info(username: str) -> str:
    if username is None or not USERNAME_RE.fullmatch(username):
        raise ValueError("Invalid username")
    pattern = f"^{username}:"

    try:
        cat = subprocess.run(
            ["/bin/cat", "/etc/passwd"],
            check=True,
            capture_output=True
        )
    except subprocess.CalledProcessError:
        raise RuntimeError("Failed to read /etc/passwd")

    grep = subprocess.run(
        ["/bin/grep", "-E", pattern],
        input=cat.stdout,
        capture_output=True
    )
    # grep returncode 1 => no matches; still fine
    return grep.stdout.decode("utf-8", errors="replace")

def main():
    if len(sys.argv) > 1:
        tests: List[str] = [sys.argv[1]]
    else:
        tests = ["root", "daemon", "bin", "nobody", "no_such_user_zzz"]

    for u in tests:
        print(f"=== Query: {u} ===")
        try:
            out = get_user_info(u)
            if out:
                print(out, end="")
            else:
                print("(no match)")
        except Exception:
            print("(error)")

if __name__ == "__main__":
    main()