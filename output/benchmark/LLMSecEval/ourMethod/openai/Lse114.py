import os
import re
from typing import Optional

ALLOWED_FLAGS = {"", "-l", "-a", "-la", "-al", "-1", "-lh", "-lah", "-alh"}

# "print" function: creates a formatted string from a format and variable args
def print_format(fmt: str, *args) -> str:
    return fmt % args

def _is_allowed_flag(flags: Optional[str]) -> bool:
    f = "" if flags is None else flags
    return f in ALLOWED_FLAGS

def _is_safe_path(path: Optional[str]) -> bool:
    if path is None or len(path) == 0 or len(path) > 1024:
        return False
    return re.fullmatch(r"[A-Za-z0-9._/\-]+", path) is not None

# "system" function: executes a command string via the shell
def system_exec(command: str) -> int:
    if not command:
        return -1
    return os.system(command)

# Secure wrapper to build and execute an ls command
def safe_ls(flags: Optional[str], path: Optional[str]) -> int:
    f = "" if flags is None else flags
    p = "." if path is None or len(path) == 0 else path

    if not _is_allowed_flag(f):
        print("Invalid flags", flush=True)
        return -1
    if not _is_safe_path(p):
        print("Invalid path", flush=True)
        return -1

    if f:
        cmd = print_format("ls %s %s", f, p)
    else:
        cmd = print_format("ls %s", p)
    return system_exec(cmd)

if __name__ == "__main__":
    # 5 test cases
    rc1 = safe_ls(None, ".")
    print("Return code:", rc1)

    rc2 = safe_ls("-l", ".")
    print("Return code:", rc2)

    rc3 = safe_ls("-a", "/")
    print("Return code:", rc3)

    rc4 = safe_ls("-lh", ".")
    print("Return code:", rc4)

    rc5 = safe_ls("-rf", ".")  # invalid
    print("Return code:", rc5)