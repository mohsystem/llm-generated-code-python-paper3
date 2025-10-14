import subprocess
import os
from typing import Set

# A whitelist of allowed directory names.
# This is the most secure way to validate input for commands.
ALLOWED_DIRECTORIES: Set[str] = {"safe_dir_1", "safe_dir_2", "."}

def list_directory_contents(directory: str) -> str:
    """
    Executes the 'ls -l' command on an allowed directory in a secure manner.

    Args:
        directory: The directory name to list. Must be in the allowed list.

    Returns:
        The output of the command or an error message.
    """
    if directory not in ALLOWED_DIRECTORIES:
        return "Error: Invalid or disallowed directory specified."

    # The command and its arguments are passed as a list.
    # This prevents the shell from interpreting the input string,
    # thus mitigating command injection vulnerabilities.
    # `shell=False` is the default and secure setting.
    command = ["ls", "-l", directory]

    try:
        # Using subprocess.run is the modern and recommended way.
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,  # Raises CalledProcessError for non-zero exit codes
            encoding='utf-8'
        )
        return result.stdout
    except FileNotFoundError:
        return f"Error: Command '{command[0]}' not found. Make sure 'ls' is in your PATH."
    except subprocess.CalledProcessError as e:
        # This captures errors from the command itself (e.g., non-zero exit code).
        return f"Error: Command failed with exit code {e.returncode}\n{e.stderr}"
    except Exception as e:
        # Catch any other unexpected errors.
        return f"An unexpected error occurred: {e}"

def main():
    """Main function with test cases."""
    # Note: For testing purposes, we create dummy directories. In a secure application,
    # file system write operations should be carefully controlled and restricted.
    for d in ["safe_dir_1", "safe_dir_2"]:
        if not os.path.exists(d):
            os.makedirs(d, exist_ok=True)

    test_cases = [
        ".",                  # A valid case (current directory)
        "safe_dir_1",         # A valid case from the whitelist
        "safe_dir_2",         # Another valid case from the whitelist
        "non_existent_dir",   # An invalid case (not in whitelist)
        "safe_dir_1; whoami", # A malicious attempt (will be rejected by the whitelist)
    ]

    for i, test_input in enumerate(test_cases, 1):
        print(f"--- Test Case {i}: Input='{test_input}' ---")
        result = list_directory_contents(test_input)
        print(result.strip())
        print(f"--- End Test Case {i} ---\n")

if __name__ == "__main__":
    main()