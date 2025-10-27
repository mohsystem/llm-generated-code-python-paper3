import subprocess
import shlex

def print_format(format_string, *args):
    """
    Creates a command string from a format string and a variable number of arguments
    using C-style string formatting.
    """
    return format_string % args

def execute_ls(command):
    """
    Executes the given command line utility string in a shell.
    It prints the standard output and standard error of the command.
    """
    print(f"Executing command: {command}")
    try:
        # Using shell=True to execute the command as a single string.
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            check=False  # Do not raise exception on non-zero exit codes
        )
        if result.stdout:
            print("--- STDOUT ---")
            print(result.stdout.strip())
        if result.stderr:
            print("--- STDERR ---")
            print(result.stderr.strip())
        print(f"Command exited with code: {result.returncode}")
    except FileNotFoundError:
        # This handles cases where the command itself (e.g., 'ls') is not found.
        cmd_name = shlex.split(command)[0]
        print(f"Error: Command '{cmd_name}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")
    print("----------------------------------------")

def main():
    # Test Case 1: ls -l
    cmd1 = print_format("%s %s", "ls", "-l")
    execute_ls(cmd1)

    # Test Case 2: ls -a
    cmd2 = print_format("%s %s", "ls", "-a")
    execute_ls(cmd2)

    # Test Case 3: ls -lh
    cmd3 = print_format("%s %s", "ls", "-lh")
    execute_ls(cmd3)

    # Test Case 4: ls /tmp
    cmd4 = print_format("%s %s", "ls", "/tmp")
    execute_ls(cmd4)

    # Test Case 5: ls -l /
    cmd5 = print_format("%s %s %s", "ls", "-l", "/")
    execute_ls(cmd5)

if __name__ == "__main__":
    main()