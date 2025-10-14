import shlex
import subprocess

ALLOWED = {"echo", "ls", "pwd", "whoami", "date", "uname", "cat"}
PROHIBITED = set("<>|;&$`(){}[]")

def _validate_tokens(tokens):
    if not tokens:
        return "empty input"
    if tokens[0] not in ALLOWED:
        return "command not allowed"
    if len(tokens) > 32:
        return "too many arguments"
    for t in tokens:
        if any(ch in PROHIBITED for ch in t):
            return "contains prohibited characters"
    if tokens[0] in ("cat", "ls"):
        for a in tokens[1:]:
            if a.startswith("-"):
                continue
            if a.startswith("/"):
                return "absolute paths are not allowed"
            if ".." in a:
                return "path traversal is not allowed"
            if "/" in a:
                return "subdirectories not allowed in arguments"
    return None

def run_command(command: str) -> str:
    try:
        tokens = shlex.split(command, posix=True)
    except Exception as e:
        return f"Invalid command: {e}"
    err = _validate_tokens(tokens)
    if err:
        return f"Invalid command: {err}"
    try:
        res = subprocess.run(tokens, capture_output=True, text=True)
        out = (res.stdout or "") + (res.stderr or "")
        return out
    except Exception as e:
        return f"Execution error: {e}"

if __name__ == "__main__":
    tests = [
        "echo Hello World",
        "pwd",
        "date",
        "uname -s",
        "ls -1",
    ]
    for t in tests:
        print("Command:", t)
        print(run_command(t))
        print("-----")