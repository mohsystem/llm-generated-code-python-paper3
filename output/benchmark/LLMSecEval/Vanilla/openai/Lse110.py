import sys
import subprocess

def run_id_command(username):
    try:
        cp = subprocess.run(["id", username])
        return cp.returncode
    except Exception:
        return 1

def main():
    if len(sys.argv) > 1:
        status = run_id_command(sys.argv[1])
        print(status)
    else:
        tests = ["root", "daemon", "nobody", "bin", "this_user_does_not_exist_12345"]
        for u in tests:
            status = run_id_command(u)
            print(f"Exit status for '{u}': {status}")

if __name__ == "__main__":
    main()