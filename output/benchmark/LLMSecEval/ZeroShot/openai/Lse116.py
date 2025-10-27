import os
import re

def is_safe_path(s: str) -> bool:
    if not s:
        return False
    return re.fullmatch(r'[A-Za-z0-9._/\-+]+', s) is not None

def print_format(fmt: str, *args) -> str:
    return fmt % args

def system(cmd: str) -> int:
    try:
        return os.system(cmd)
    except Exception:
        return -1

def ls_command(directory: str) -> int:
    if not is_safe_path(directory):
        print(f"Rejected unsafe path: {directory}")
        return -1
    cmd = print_format("/bin/ls -la -- %s", directory)
    return system(cmd)

if __name__ == "__main__":
    tests = [
        ".",
        "src",
        "/tmp",
        "does-not-exist",
        "bad;rm -rf /"
    ]
    for t in tests:
        print(f"Running ls on: {t}")
        status = ls_command(t)
        print(f"Exit status: {status}")
        print("----")