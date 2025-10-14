import platform
import re
import subprocess

OUTPUT_LIMIT = 8192
TIMEOUT_SECONDS = 5

def run_ping(user_input: str) -> str:
    if not _is_valid_host(user_input):
        return "Invalid input"
    is_windows = platform.system().lower().startswith("win")
    cmd = ["ping", "-n", "1", user_input] if is_windows else ["ping", "-c", "1", user_input]
    try:
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS
        )
        out = (res.stdout or "") + (res.stderr or "")
        if len(out) > OUTPUT_LIMIT:
            out = out[:OUTPUT_LIMIT]
        return out
    except subprocess.TimeoutExpired:
        return "Timed out"
    except Exception:
        return "Execution failed"

def _is_valid_host(s: str) -> bool:
    if not isinstance(s, str):
        return False
    if len(s) < 1 or len(s) > 253:
        return False
    return re.fullmatch(r"[A-Za-z0-9.-]+", s) is not None

if __name__ == "__main__":
    tests = [
        "localhost",
        "127.0.0.1",
        "example.com",
        "bad;rm -rf /",
        "name with spaces",
    ]
    for t in tests:
        print("Input:", t)
        print("Output (truncated):")
        print(run_ping(t))
        print("----")