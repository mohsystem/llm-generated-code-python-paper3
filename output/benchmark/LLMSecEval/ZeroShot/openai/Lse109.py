import subprocess
import sys
import re

def is_valid_username(username: str) -> bool:
    if not isinstance(username, str) or len(username) == 0 or len(username) > 32:
        return False
    return re.fullmatch(r"[A-Za-z0-9_.-]+", username) is not None

# Execute a pipeline cmd1 | cmd2 where each cmd is a list of args
def exec_pipeline(cmd1, cmd2, timeout=5):
    p1 = subprocess.Popen(cmd1, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, close_fds=True)
    try:
        p2 = subprocess.Popen(cmd2, stdin=p1.stdout, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, close_fds=True)
        if p1.stdout:
            p1.stdout.close()
        out, _ = p2.communicate(timeout=timeout)
        # Ensure p1 exits as well
        try:
            p1.wait(timeout=max(0.1, timeout - 0.1))
        except subprocess.TimeoutExpired:
            p1.kill()
        return out.decode('utf-8', errors='replace')
    except Exception:
        try:
            p1.kill()
        except Exception:
            pass
        return ""

def get_user_info(username: str) -> str:
    if not is_valid_username(username):
        return ""
    cmd1 = ["/bin/cat", "/etc/passwd"]
    cmd2 = ["/bin/grep", "-F", username]
    return exec_pipeline(cmd1, cmd2)

if __name__ == "__main__":
    tests = [
        sys.argv[1] if len(sys.argv) > 1 else "root",
        "daemon",
        "bin",
        "nosuchuser",
        "invalid;rm"
    ]
    for u in tests:
        print(f"Query: {u}")
        out = get_user_info(u)
        print(out, end="")
        if not out:
            print("(no output or invalid username)")
        print("-----")