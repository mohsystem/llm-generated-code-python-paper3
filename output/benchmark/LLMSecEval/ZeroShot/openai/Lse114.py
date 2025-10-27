import os
import shlex

def print_format(fmt, *args):
    return fmt % args

def shell_quote(s: str) -> str:
    if s is None or s == "":
        return "''"
    return shlex.quote(s)

def run_ls(path: str | None = None) -> int:
    base = "/bin/ls -la"
    if path:
        cmd = print_format("%s %s", base, shell_quote(path))
    else:
        cmd = base
    return os.system(cmd)

if __name__ == "__main__":
    tests = [None, ".", "/", "/tmp", "no_such_file_xyz"]
    for t in tests:
        print(f"== Python run_ls({t}) ==")
        run_ls(t)