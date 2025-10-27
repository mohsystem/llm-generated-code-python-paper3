import os
import re
from typing import Tuple

# Build a command string using a format string and variable arguments (print-like).
def print_format(fmt: str, *args) -> str:
    if fmt is None:
        return ""
    try:
        cmd = (fmt % args) if args else fmt
    except Exception:
        return ""
    cmd = cmd.strip()
    if len(cmd) == 0 or len(cmd) > 256:
        return ""
    return cmd

_SAFE_RE = re.compile(r"^ls(?: [A-Za-z0-9._/\-]+)?$")

def _is_safe_ls_command(cmd: str) -> bool:
    if not isinstance(cmd, str):
        return False
    s = cmd.strip()
    if len(s) < 2 or len(s) > 256:
        return False
    if not _SAFE_RE.match(s):
        return False
    # If there is an argument, block traversal
    parts = s.split(" ", 1)
    if len(parts) == 2 and ".." in parts[1]:
        return False
    return True

# "system"-like function to execute the command string.
# Returns the exit status code (0 usually means success).
def safe_system(command: str) -> int:
    if not _is_safe_ls_command(command):
        print("Rejected command")
        return -1
    # Using os.system as requested; output goes to the console.
    try:
        return os.system(command)
    except Exception:
        return -1

# Convenience function to format and run ls.
def run_ls_formatted(fmt: str, *args) -> int:
    cmd = print_format(fmt, *args)
    return safe_system(cmd)

def main():
    # 5 test cases
    r1 = run_ls_formatted("ls")
    print(f"Exit: {r1}")

    r2 = run_ls_formatted("ls %s", ".")
    print(f"Exit: {r2}")

    r3 = run_ls_formatted("ls %s", "/")
    print(f"Exit: {r3}")

    r4 = run_ls_formatted("ls %s", "./")
    print(f"Exit: {r4}")

    r5 = run_ls_formatted("ls %s", "nonexistent_path_should_fail")
    print(f"Exit: {r5}")

if __name__ == "__main__":
    main()