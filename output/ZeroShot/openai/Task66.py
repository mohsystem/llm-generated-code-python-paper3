import subprocess
import shlex
import sys
import os
from typing import List

ALLOWED_CMDS = {"echo", "date", "uname", "whoami", "pwd", "ls"}
UNAME_OPTS = {"-a", "-s", "-r", "-m", "-n"}
LS_OPTS = {"-l", "-a", "-la", "-al", "-lah", "-hal", "-hla", "-alh"}
MAX_INPUT_LEN = 200
MAX_OUTPUT_BYTES = 8192
TIMEOUT_SECONDS = 5.0

def _all_chars_allowed(s: str) -> bool:
    allowed_extra = set(" ._/-:=+,")
    for ch in s:
        if ch.isalnum() or ch in allowed_extra:
            continue
        return False
    return True

def _safe_token(tok: str) -> bool:
    if not tok or len(tok) > 128:
        return False
    allowed_extra = set("._/-:=+,")
    for ch in tok:
        if ch.isalnum() or ch in allowed_extra:
            continue
        return False
    return True

def _safe_path(p: str) -> bool:
    if not _safe_token(p):
        return False
    if p.startswith("/"):
        return False
    if ".." in p:
        return False
    return True

def run_safe_command(command: str) -> str:
    if command is None:
        return "INVALID: empty"
    s = command.strip()
    if not s:
        return "INVALID: empty"
    if len(s) > MAX_INPUT_LEN:
        return "INVALID: too long"
    if not _all_chars_allowed(s):
        return "INVALID: contains disallowed characters"

    parts: List[str] = s.split()
    if not parts:
        return "INVALID: empty"
    cmd = parts[0]
    if cmd not in ALLOWED_CMDS:
        return "INVALID: command not allowed"

    args: List[str] = [cmd]
    if cmd == "echo":
        for t in parts[1:]:
            if t.startswith("-"):
                return "INVALID: echo options not allowed"
            if not _safe_token(t):
                return "INVALID: unsafe token"
            args.append(t)
    elif cmd == "date":
        if len(parts) > 1:
            return "INVALID: date takes no arguments"
    elif cmd == "uname":
        if len(parts) > 2:
            return "INVALID: too many args for uname"
        if len(parts) == 2:
            if parts[1] not in UNAME_OPTS:
                return "INVALID: uname option not allowed"
            args.append(parts[1])
    elif cmd in ("whoami", "pwd"):
        if len(parts) > 1:
            return "INVALID: command takes no arguments"
    elif cmd == "ls":
        path_seen = False
        for t in parts[1:]:
            if t.startswith("-"):
                if t not in LS_OPTS:
                    return "INVALID: ls option not allowed"
                args.append(t)
            else:
                if path_seen:
                    return "INVALID: only one path allowed"
                if not _safe_path(t):
                    return "INVALID: unsafe path"
                args.append(t)
                path_seen = True
    else:
        return "INVALID: command not allowed"

    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=TIMEOUT_SECONDS, shell=False)
    except subprocess.TimeoutExpired:
        return "ERROR: timeout"
    except Exception:
        return "ERROR: cannot start process"

    out = (proc.stdout or "") + (proc.stderr or "")
    if len(out.encode("utf-8", errors="ignore")) > MAX_OUTPUT_BYTES:
        out = out.encode("utf-8", errors="ignore")[:MAX_OUTPUT_BYTES].decode("utf-8", errors="ignore") + "\n[truncated]"
    return out

if __name__ == "__main__":
    tests = [
        "echo hello",
        "date",
        "uname -a",
        "ls -l",
        "pwd",
    ]
    for t in tests:
        print(f"Command: {t}")
        print("Output:\n" + run_safe_command(t))
        print("----")