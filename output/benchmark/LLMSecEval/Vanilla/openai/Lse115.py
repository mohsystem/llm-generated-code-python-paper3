import subprocess
import sys

def print(fmt, *args):
    return (fmt % args) if args else fmt

def exec_command(cmd: str) -> str:
    try:
        res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        return res.stdout
    except Exception as e:
        return str(e) + "\n"

def main():
    cmds = [
        print("ls %s", "-1"),
        print("ls"),
        print("ls %s %s", "-a", "-1"),
        print("ls %s %s", "-l", "."),
        print("ls %s", "this_path_does_not_exist"),
    ]
    for cmd in cmds:
        sys.stdout.write("Command: " + cmd + "\n")
        sys.stdout.write(exec_command(cmd))

if __name__ == "__main__":
    main()