import subprocess
import sys
from typing import Optional


def build_string(fmt: str, *args) -> str:
    if not isinstance(fmt, str):
        return ""
    try:
        s = fmt % args
    except Exception:
        return ""
    if not _is_safe_path(s):
        return ""
    return s


def _is_safe_path(s: Optional[str]) -> bool:
    if s is None:
        return False
    if len(s) > 255:
        return False
    if "\x00" in s:
        return False
    if ".." in s:
        return False
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-/")
    return all(c in allowed for c in s)


def execute_ls(input_str: Optional[str]) -> str:
    path = input_str if input_str else "."
    if not _is_safe_path(path):
        return "error: invalid input\n"
    try:
        # Execute without shell to avoid injection
        proc = subprocess.run(
            ["ls", "--", path],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        return proc.stdout + (proc.stderr or "")
    except Exception:
        return "error: execution failed\n"


def main() -> None:
    tests = [
        build_string("%s", "."),
        build_string("%s", "/"),
        build_string("nonexistent_%s", "dir"),
        build_string("%s/%s", "tmp", "test"),
        build_string("%s%s", ".", ""),
    ]
    for i, t in enumerate(tests, 1):
        print(f"=== Test {i} ===")
        print(execute_ls(t), end="")


if __name__ == "__main__":
    main()