import os

# "print" function: creates a formatted string from a format and variable arguments
def print_fmt(fmt, *args):
    if not args:
        return fmt
    return fmt % args

# "system" function: executes a command and returns the exit code
def system(cmd):
    return os.system(cmd)

# Convenience function combining print + system
def execf(fmt, *args):
    cmd = print_fmt(fmt, *args)
    return system(cmd)

# 5 test cases
if __name__ == "__main__":
    r1 = execf("ls")
    r2 = execf("ls %s", "-l")
    r3 = execf("ls %s %s", "-a", ".")
    r4 = execf("ls %s", "--color=auto")
    r5 = execf("ls %s", "..")
    print("Exit codes:")
    print(r1)
    print(r2)
    print(r3)
    print(r4)
    print(r5)