import os

def print(fmt, *args):
    return fmt % args

def run_ls(options, directory):
    if options is None:
        options = ""
    if directory is None or directory == "":
        directory = "."
    cmd = print("ls %s %s", options, directory)
    return os.system(cmd)

if __name__ == "__main__":
    run_ls("", ".")
    run_ls("-l", ".")
    run_ls("-a", ".")
    run_ls("-la", ".")
    run_ls("", "..")