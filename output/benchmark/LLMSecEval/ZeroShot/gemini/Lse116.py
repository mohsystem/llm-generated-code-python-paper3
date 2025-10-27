import subprocess

def execute_ls_command(directory: str) -> int:
    """
    Securely executes the 'ls' command on a given directory.
    Uses subprocess.run with a list of arguments (shell=False by default) 
    to prevent shell injection vulnerabilities.

    Args:
        directory: The directory path to list.
    
    Returns:
        The exit code of the command, or -1 on error.
    """
    if not isinstance(directory, str) or not directory:
        print("Error: Directory path must be a non-empty string.")
        return -1

    print(f"--- Executing 'ls {directory}' ---")
    
    # The command and its arguments are passed as a list.
    # This ensures that 'directory' is treated as a single argument
    # and is not interpreted by the shell.
    command = ["ls", directory]
    
    try:
        # subprocess.run is the modern and recommended way to run external commands.
        result = subprocess.run(
            command, 
            capture_output=True, 
            text=True, 
            check=False  # Do not raise exception on non-zero exit codes
        )

        # Print standard output
        if result.stdout:
            print(result.stdout.strip())

        # Print standard error
        if result.stderr:
            print(f"Error output:\n{result.stderr.strip()}")

        print(f"Exited with code: {result.returncode}")
        print("------------------------------------")
        return result.returncode

    except FileNotFoundError:
        print("Error: 'ls' command not found. Please ensure it is in your system's PATH.")
        print("------------------------------------")
        return -1
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        print("------------------------------------")
        return -1

# Test Case 1: Current directory
execute_ls_command(".")

# Test Case 2: A common, valid directory like /tmp
execute_ls_command("/tmp")

# Test Case 3: A non-existent directory
execute_ls_command("/non_existent_dir_12345")

# Test Case 4: A potentially malicious string.
# subprocess will treat this as a single, literal argument. `ls` will safely
# report that the file/directory does not exist, and no command is injected.
execute_ls_command("&& whoami")

# Test Case 5: Another potentially malicious string.
# This is also handled safely as a literal filename.
execute_ls_command(";/bin/bash")