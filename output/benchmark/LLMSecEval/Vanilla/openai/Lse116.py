import os

def print_fmt(fmt, *args):
    return (fmt % args) if args else fmt

def run_command(fmt, *args):
    cmd = print_fmt(fmt, *args)
    return os.system(cmd)

if __name__ == "__main__":
    run_command("ls")
    run_command("ls %s", "-l")
    run_command("ls %s", "-a")
    run_command("ls %s %s", "-l", ".")
    run_command("ls %s", "-1")