import subprocess
import sys

def exec_command(command: str) -> str:
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return result.stdout

def get_user_info(username: str) -> str:
    return exec_command(f"cat /etc/passwd | grep {username}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        print(get_user_info(sys.argv[1]), end="")
    else:
        tests = ["root", "daemon", "bin", "sys", "nobody"]
        for u in tests:
            print(get_user_info(u), end="")