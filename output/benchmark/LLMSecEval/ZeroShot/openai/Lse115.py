import os
import re
import subprocess

def sprint(fmt: str, *args) -> str:
    if fmt is None:
        raise ValueError("Format string cannot be None")
    # Use printf-style formatting for simplicity
    return fmt % args if args else fmt

_SAFE_RE = re.compile(r'^[A-Za-z0-9 ./_\-]+$')

def _is_safe_path(s: str) -> bool:
    if s is None or len(s) == 0:
        return False
    if len(s) > 4096:
        return False
    if s[0] == '-':
        return False
    return _SAFE_RE.match(s) is not None

def execute_ls(arg: str) -> str:
    path = "." if (arg is None or arg == "") else arg
    if not _is_safe_path(path):
        return "Invalid or unsafe path input.\n"
    try:
        cp = subprocess.run(
            ["ls", "--color=never", "--", path],
            capture_output=True,
            text=True,
            check=False
        )
        out = (cp.stdout or "") + (cp.stderr or "")
        # Limit output to 10MB for safety
        if len(out) > 10 * 1024 * 1024:
            out = out[:10 * 1024 * 1024] + "\n[Output truncated]\n"
        return out
    except Exception as e:
        return f"Execution failed: {e}\n"

if __name__ == "__main__":
    tests = [
        sprint("%s", "."),
        sprint("%s", "/"),
        sprint("%s", ".."),
        sprint("./%s", "nonexistent_dir_hopefully"),
        sprint("%s-%s", "src", "main"),
    ]
    for i, t in enumerate(tests, 1):
        res = execute_ls(t)
        print(f"Test {i} input: {t}")
        print(res)
        print("----")