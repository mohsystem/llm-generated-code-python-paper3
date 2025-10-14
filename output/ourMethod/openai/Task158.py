import re
import subprocess
import sys
from typing import List

def _is_valid_input(s: str) -> bool:
    if not isinstance(s, str):
        return False
    if len(s) < 1 or len(s) > 64:
        return False
    return re.fullmatch(r"[A-Za-z0-9 _:\-\.]{1,64}", s) is not None

def run_safe_echo(user_input: str) -> str:
    if not _is_valid_input(user_input):
        return "ERROR: Invalid input. Allowed: 1-64 chars [A-Za-z0-9 _:-.]"

    if sys.platform.startswith("win"):
        cmd: List[str] = ["powershell", "-NoProfile", "-NonInteractive", "-Command", "Write-Output", user_input]
    else:
        # Prefer /usr/bin/printf, fallback to /bin/printf
        printf_path = "/usr/bin/printf"
        try:
            subprocess.run([printf_path, "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            printf_path = "/bin/printf"
        cmd = [printf_path, "%s\n", user_input]

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
        return res.stdout
    except subprocess.TimeoutExpired:
        return "ERROR: Command timed out."
    except FileNotFoundError:
        return "ERROR: Required command not found."
    except Exception as e:
        return f"ERROR: {str(e)}"

def main() -> None:
    tests = [
        "HelloWorld",
        "Safe_123",
        "alpha-beta",
        "COLON:TEST",
        "Numbers 0123456789",
    ]
    for t in tests:
        out = run_safe_echo(t)
        print(f"Input: {t}")
        print(f"Output: {out}")
        print("-----")

if __name__ == "__main__":
    main()