import os
import re
import subprocess
import sys

SAFE_PATTERN = re.compile(r'^[A-Za-z0-9 _\.,:@%+/=\-/]*$')
MAX_LEN = 200

def is_safe(s: str) -> bool:
    return s is not None and len(s) <= MAX_LEN and SAFE_PATTERN.fullmatch(s) is not None

def run_echo(input_str: str) -> str:
    if not is_safe(input_str):
        raise ValueError("Input contains disallowed characters or is too long.")
    if os.name == 'nt':
        cmd = ["cmd.exe", "/c", "echo", input_str]
    else:
        cmd = ["/bin/echo", input_str]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"Process exited with {res.returncode}")
    return res.stdout.rstrip("\r\n")

if __name__ == "__main__":
    try:
        # 5 test cases
        print(run_echo("Hello World"))
        print(run_echo("Sample_123"))
        print(run_echo("Path/with/slash"))
        print(run_echo("Value+Plus=Equals"))
        print(run_echo("Email: user@example.com"))

        # Interactive input
        user_input = sys.stdin.readline()
        if user_input is None:
            user_input = ""
        else:
            user_input = user_input.rstrip("\r\n")
        print(run_echo(user_input))
    except Exception as e:
        print(f"Error: {e}")