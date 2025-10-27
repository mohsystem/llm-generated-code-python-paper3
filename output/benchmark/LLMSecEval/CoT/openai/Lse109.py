import re
import subprocess
import sys

def validate_username(username: str) -> None:
    if not isinstance(username, str) or len(username) == 0 or len(username) > 64:
        raise ValueError("Invalid username")
    if not re.fullmatch(r'[A-Za-z0-9_.-]+', username):
        raise ValueError("Invalid username")

def execute_pipeline(cmd1, cmd2) -> str:
    # Execute cmd1 | cmd2 and return stdout of cmd2 as string
    p1 = subprocess.Popen(cmd1, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=False)
    try:
        p2 = subprocess.Popen(cmd2, stdin=p1.stdout, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=False)
        # Close p1 stdout in parent so p2 can get EOF
        if p1.stdout:
            p1.stdout.close()
        out, _ = p2.communicate()
        p1.wait()
        return out.decode('utf-8', errors='replace')
    finally:
        try:
            p1.kill()
        except Exception:
            pass

def get_user_info(username: str) -> str:
    validate_username(username)
    cmd1 = ["cat", "/etc/passwd"]
    cmd2 = ["grep", "-F", "--", username]
    return execute_pipeline(cmd1, cmd2)

if __name__ == "__main__":
    try:
        if len(sys.argv) > 1:
            print(get_user_info(sys.argv[1]), end="")
        else:
            # 5 test cases
            for u in ["root", "daemon", "nobody", "bin", "thisuserdoesnotexist123"]:
                print(get_user_info(u), end="")
    except Exception:
        print("", end="")