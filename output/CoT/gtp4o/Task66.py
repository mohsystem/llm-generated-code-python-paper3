# Chain-of-Through steps applied:
# 1) Understand: Safely validate and execute a limited set of bash-like commands and return output.
# 2) Security: No shell=True, strict allowlist, forbid metachars, bounded inputs/time/output.
# 3) Implement: Use subprocess.run([...], shell=False), validation helpers, timeout, output cap.
# 4) Review: Ensure no injection path, strict chars, restricted args/paths, safe binaries.
# 5) Finalize: Provide safe function and 5 test cases.

import subprocess
import shutil
import os
import re
from typing import List

MAX_CMD_LEN = 256
MAX_ARGS = 8
MAX_OUTPUT_BYTES = 1_000_000
TIMEOUT_SEC = 3

ALLOWED_CMDS = {"echo", "ls", "pwd", "whoami", "date", "uname", "cat"}
FORBIDDEN_CHARS_RE = re.compile(r"[;|&><`$(){}\[\]\\'\"*!?~\r\n\t]")

SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9._/\-=:@,+%]{1,128}$")

def is_safe_token(t: str) -> bool:
    return bool(SAFE_TOKEN_RE.match(t))

def is_safe_path_arg(t: str) -> bool:
    if not is_safe_token(t):
        return False
    if t.startswith("/"):
        return False
    if t.startswith("-"):
        return False
    if ".." in t:
        return False
    return True

def is_ls_flag(t: str) -> bool:
    if not t.startswith("-") or len(t) < 2:
        return False
    return all(ch in "lah1" for ch in t[1:])

def tokenize(s: str) -> List[str]:
    return [p for p in s.strip().split() if p]

def validate_tokens(tokens: List[str]) -> bool:
    if not tokens or len(tokens) > MAX_ARGS:
        return False
    cmd = tokens[0]
    if cmd not in ALLOWED_CMDS:
        return False
    args = tokens[1:]
    if cmd in ("pwd", "whoami", "date"):
        return len(args) == 0
    if cmd == "uname":
        return len(args) == 0 or (len(args) == 1 and args[0] == "-a")
    if cmd == "echo":
        if len(args) > 5:
            return False
        return all(is_safe_token(a) for a in args)
    if cmd == "ls":
        if len(args) > 2:
            return False
        saw_path = False
        for a in args:
            if a.startswith("-"):
                if not is_ls_flag(a):
                    return False
            else:
                if saw_path:
                    return False
                if not is_safe_path_arg(a):
                    return False
                saw_path = True
        return True
    if cmd == "cat":
        if len(args) == 0 or len(args) > 2:
            return False
        return all(is_safe_path_arg(a) for a in args)
    return False

def resolve_absolute(cmd: str) -> str:
    for p in (f"/bin/{cmd}", f"/usr/bin/{cmd}"):
        if os.path.exists(p) and os.access(p, os.X_OK):
            return p
    return ""

def run_safe_command(cmd: str) -> str:
    if cmd is None or not isinstance(cmd, str):
        return "Error: Empty input"
    if len(cmd) > MAX_CMD_LEN:
        return "Error: Command too long"
    if FORBIDDEN_CHARS_RE.search(cmd):
        return "Error: Forbidden characters present"
    if any(ord(c) < 32 or ord(c) > 126 for c in cmd):
        return "Error: Invalid characters present"

    tokens = tokenize(cmd)
    if not validate_tokens(tokens):
        return "Error: Command not allowed or invalid arguments"

    abs_bin = resolve_absolute(tokens[0])
    if not abs_bin:
        return "Error: Command binary not found"
    tokens[0] = abs_bin

    try:
        # Clear sensitive env vars
        env = os.environ.copy()
        env.pop("LD_PRELOAD", None)
        env.pop("LD_LIBRARY_PATH", None)
        res = subprocess.run(tokens, capture_output=True, text=False, timeout=TIMEOUT_SEC, env=env)
        out = res.stdout + res.stderr
        if len(out) > MAX_OUTPUT_BYTES:
            out = out[:MAX_OUTPUT_BYTES] + b"\n[Truncated output]"
        try:
            return out.decode("utf-8", errors="replace")
        except Exception:
            return "[Error] Output decode failed"
    except subprocess.TimeoutExpired:
        return "[Error] Execution timed out"
    except Exception:
        return "Error: Execution failed"

if __name__ == "__main__":
    tests = [
        "pwd",
        "whoami",
        "date",
        "echo safe_test",
        "ls -l"
    ]
    for t in tests:
        print(">>>", t)
        print(run_safe_command(t))