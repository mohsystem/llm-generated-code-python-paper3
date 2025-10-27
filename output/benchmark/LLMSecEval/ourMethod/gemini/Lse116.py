import os
import re
import sys
import shlex

# A pattern to validate arguments, following a whitelist approach.
# Allows:
# - options starting with '-' (e.g., -l, -a)
# - file/directory paths (alphanumeric, /, ., _, -)
# - wildcards like '*' or '?' for shell globbing.
# Disallows shell metacharacters (`&`, `|`, `;`, `$`, etc.) that could lead to command injection.
VALID_ARG_PATTERN = re.compile(r"^[a-zA-Z0-9_\.\/\*\?\-]+$")

def execute_ls_command(*args):
    """
    Executes the 'ls' command using os.system.
    This function validates each argument to prevent command injection.

    Note: Using subprocess.run with shell=False is generally safer.
    This implementation uses os.system to match the prompt's requirements.

    :param args: A variable number of string arguments for the 'ls' command.
    """
    command_parts = ["ls"]
    for arg in args:
        if not arg:
            continue
        # SECURITY: Validate each argument against a whitelist pattern to prevent command injection.
        if not VALID_ARG_PATTERN.match(arg):
            print(f"Error: Invalid or potentially malicious argument detected: {arg}", file=sys.stderr)
            return

        # Use shlex.quote for an additional layer of safety, correctly handling arguments.
        command_parts.append(shlex.quote(arg))

    # The 'print function' (f-string/join) is used to create the string.
    command = " ".join(command_parts)
    print(f"Executing command: {command}")

    # The system function executes the command in a subshell.
    # The return value is the exit status.
    exit_code_raw = os.system(command)
    
    # On POSIX, os.system's return value is encoded. WEXITSTATUS decodes it.
    if os.name == 'posix':
        if os.WIFEXITED(exit_code_raw):
            exit_code = os.WEXITSTATUS(exit_code_raw)
        else:
            exit_code = -1 # Indicate non-normal termination
    else:
        exit_code = exit_code_raw

    print(f"Exit Code: {exit_code}")


def main():
    """Main function with test cases."""
    print("--- Test Case 1: ls current directory ---")
    execute_ls_command()

    print("\n--- Test Case 2: ls -l -a ---")
    execute_ls_command("-l", "-a")

    print("\n--- Test Case 3: ls specific path ---")
    execute_ls_command(".") # Use a safe, known path

    print("\n--- Test Case 4: ls non-existent file (shows error stream) ---")
    execute_ls_command("/non_existent_dir_12345")
    
    print("\n--- Test Case 5: Attempted command injection (should be rejected) ---")
    execute_ls_command("-l;id")

if __name__ == "__main__":
    main()