import subprocess
import shlex

def execute_ls(*args):
    """
    Executes the 'ls' command with specified arguments in a secure way.
    
    This function uses the `subprocess` module, which is the standard and secure
    way to run external commands in Python. The command and its arguments are
    passed as a list, which prevents command injection vulnerabilities.
    Using `os.system()` with a formatted string is highly discouraged as it is
    vulnerable to shell injection if arguments come from an untrusted source.
    
    :param args: A variable number of string arguments for the 'ls' command.
    """
    # The base command is 'ls'. All other arguments are appended to this list.
    # This prevents the shell from interpreting the arguments, which is key to security.
    command = ["ls"] + list(args)

    # For display purposes, we can show what the command would look like in a shell.
    # shlex.join is used for safe shell-style string representation.
    print(f"Executing: {shlex.join(command)}")
    print("------------------------------------")
    
    try:
        # `capture_output=True` captures stdout and stderr.
        # `text=True` decodes them as text.
        # `check=False` prevents raising an exception for non-zero exit codes,
        # allowing us to handle them gracefully.
        result = subprocess.run(command, capture_output=True, text=True, check=False)

        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="")
            
        print("------------------------------------")
        print(f"Exited with code: {result.returncode}")
        print()

    except FileNotFoundError:
        print("Error: 'ls' command not found. Is it in your PATH?")
        print("------------------------------------")
        print("Exited with code: -1")
        print()
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        print("------------------------------------")
        print("Exited with code: -1")
        print()

if __name__ == "__main__":
    print("--- Test Case 1: ls -l . ---")
    execute_ls("-l", ".")

    print("--- Test Case 2: ls -a / ---")
    execute_ls("-a", "/")

    print("--- Test Case 3: ls (no arguments) ---")
    execute_ls()

    print("--- Test Case 4: ls /tmp ---")
    execute_ls("/tmp")

    print("--- Test Case 5: ls /non_existent_directory_xyz ---")
    execute_ls("/non_existent_directory_xyz")