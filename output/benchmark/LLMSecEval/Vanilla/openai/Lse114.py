import os

# "print" function equivalent: returns a formatted string.
def printf(fmt, *args):
    if args:
        try:
            return fmt % args
        except TypeError:
            return fmt.format(*args)
    return fmt

# "system" function: executes the provided command string.
def system_run(cmd):
    return os.system(cmd)

# Convenience function: format and execute.
def system_runf(fmt, *args):
    return system_run(printf(fmt, *args))

if __name__ == "__main__":
    # 5 test cases using ls with different arguments
    system_runf("ls")
    system_runf("ls %s", "-l")
    system_runf("ls %s %s", "-l", "-a")
    system_runf("ls %s %s %s", "-l", "-a", ".")
    system_runf("ls %s", ".")