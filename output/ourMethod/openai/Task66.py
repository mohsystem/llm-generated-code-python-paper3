import os
import subprocess
from typing import List

MAX_INPUT_LENGTH = 256
MAX_OUTPUT_CHARS = 100_000
TIMEOUT_SECONDS = 5

ALLOWED_COMMANDS = {"echo", "date", "uname", "whoami", "pwd", "ls"}
ALLOWED_UNAME_FLAGS = {"-a", "-s", "-r", "-m"}
ALLOWED_LS_FLAGS = {"-l", "-a", "-la", "-al"}

def _has_forbidden_chars(s: str) -> bool:
    forbidden = set(";|&`$()<>\"'\\")
    return any(c in forbidden for c in s)

def _safe_echo_token(tok: str) -> bool:
    if not (1 <= len(tok) <= 64):
        return False
    for c in tok:
        if not (c.isalnum() or c in "._,@:+-"):
            return False
    return True

def execute_validated_command(base_dir: str, user_input: str) -> str:
    if not base_dir:
        return "ERROR: invalid base directory."
    if user_input is None:
        return "ERROR: null input."
    s = user_input.strip()
    if not s or len(s) > MAX_INPUT_LENGTH:
        return "ERROR: input length invalid."
    if _has_forbidden_chars(s):
        return "ERROR: input contains forbidden characters."

    tokens = s.split()
    if not tokens:
        return "ERROR: empty command."
    cmd = tokens[0]
    if cmd not in ALLOWED_COMMANDS:
        return "ERROR: command not allowed."

    argv: List[str] = []
    if cmd == "echo":
        argv.append("echo")
        for t in tokens[1:]:
            if not _safe_echo_token(t):
                return "ERROR: echo argument contains invalid characters or length."
            argv.append(t)
    elif cmd == "date":
        if len(tokens) != 1:
            return "ERROR: 'date' takes no arguments."
        argv = ["date"]
    elif cmd == "whoami":
        if len(tokens) != 1:
            return "ERROR: 'whoami' takes no arguments."
        argv = ["whoami"]
    elif cmd == "pwd":
        if len(tokens) != 1:
            return "ERROR: 'pwd' takes no arguments."
        argv = ["pwd"]
    elif cmd == "uname":
        if len(tokens) == 1:
            argv = ["uname"]
        elif len(tokens) == 2 and tokens[1] in ALLOWED_UNAME_FLAGS:
            argv = ["uname", tokens[1]]
        else:
            return "ERROR: invalid 'uname' usage."
    elif cmd == "ls":
        if len(tokens) == 1:
            argv = ["ls"]
        elif len(tokens) == 2 and tokens[1] in ALLOWED_LS_FLAGS:
            argv = ["ls", tokens[1]]
        else:
            return "ERROR: only simple 'ls' flags allowed (no paths)."
    else:
        return "ERROR: command not allowed."

    try:
        proc = subprocess.run(
            argv,
            cwd=base_dir,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
            check=False,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        if len(out) > MAX_OUTPUT_CHARS:
            out = out[:MAX_OUTPUT_CHARS]
        return f"exit={proc.returncode}\n{out}"
    except subprocess.TimeoutExpired:
        return "ERROR: execution timed out."
    except Exception:
        return "ERROR: execution failure."

def main() -> None:
    base_dir = os.getcwd()
    tests = [
        "echo Hello_World",
        "date",
        "uname -s",
        "ls -a",
        "ls /"  # should be rejected
    ]
    for t in tests:
        res = execute_validated_command(base_dir, t)
        print(f"TEST> {t}")
        print(res)
        print("----")
    try:
        cmd = input("Enter a command:\n")
    except Exception:
        print("ERROR: failed to read input.")
        return
    print(execute_validated_command(base_dir, cmd))

if __name__ == "__main__":
    main()