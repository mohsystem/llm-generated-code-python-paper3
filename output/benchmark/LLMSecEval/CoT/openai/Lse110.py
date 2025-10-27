# Chain-of-Through process in code generation:
# 1) Problem understanding: Function takes username, runs '/usr/bin/id -- <username>', returns exit status; print exit status.
# 2) Security requirements: Avoid shell, use absolute path, prevent option injection via '--', handle exceptions safely.
# 3) Secure coding generation: Use subprocess.run with list args, inherit IO, return returncode.
# 4) Code review: No shell, absolute path used, '--' used, exceptions mapped to return codes.
# 5) Secure code output: Final code with robust handling and 5 test cases.

import subprocess
import sys

def run_id(username: str) -> int:
    if username is None or username == "":
        return 2  # invalid input
    try:
        # Inherit parent's stdout/stderr so 'id' prints directly
        result = subprocess.run(["/usr/bin/id", "--", username], check=False)
        return int(result.returncode)
    except KeyboardInterrupt:
        return 130
    except FileNotFoundError:
        return 127
    except Exception:
        return 1

if __name__ == "__main__":
    if len(sys.argv) >= 2:
        status = run_id(sys.argv[1])
        print(f"Exit status: {status}")
    else:
        # 5 test cases
        tests = ["root", "nobody", "daemon", "www-data", "user_does_not_exist_123456"]
        for u in tests:
            status = run_id(u)
            print(f"Username: {u} -> Exit status: {status}")