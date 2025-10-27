import subprocess
import shlex
import sys
import re

# A pattern to validate arguments. It allows alphanumeric characters, dashes, dots, and slashes.
# This is a restrictive whitelist to prevent command injection.
# It does not prevent path traversal (e.g., "ls ../../"), which could be an information disclosure vulnerability.
SAFE_ARG_PATTERN = re.compile(r'^[a-zA-Z0-9_./-]+$')

def create_command_string(format_str: str, *args) -> str:
    """
    Creates a command string using a format string and arguments.
    This function simply formats a string and is not inherently insecure,
    but the string it produces must be handled with care.
    """
    return format_str.format(*args)

def execute_ls_command(command: str):
    """
    Executes an 'ls' command provided as a single string.
    The command string is parsed and validated before execution to prevent
    command injection vulnerabilities. It specifically avoids using a shell.
    """
    if not command:
        print("Error: Command string is null or empty.", file=sys.stderr)
        return

    try:
        # Use shlex.split to safely parse the command string, respecting quotes.
        parts = shlex.split(command)
        if not parts:
            print("Error: Invalid command format.", file=sys.stderr)
            return

        # Security Check 1: The command must be exactly 'ls'.
        # This prevents executing arbitrary commands.
        if parts[0] != 'ls':
            print(f"Error: Only 'ls' command is allowed. Found: {parts[0]}", file=sys.stderr)
            return

        # Security Check 2: Validate all arguments against a safe pattern.
        # This prevents shell metacharacters and other injection attacks.
        for arg in parts[1:]:
            if not SAFE_ARG_PATTERN.match(arg):
                print(f"Error: Argument contains invalid characters: {arg}", file=sys.stderr)
                return

        # Use subprocess.run with the parsed list.
        # shell=False (the default) is crucial for security as it prevents shell interpretation.
        result = subprocess.run(
            parts, 
            capture_output=True, 
            text=True, 
            check=False
        )
        
        if result.stdout:
            print(result.stdout, end='')
        if result.stderr:
            print(result.stderr, file=sys.stderr, end='')
        
        if result.returncode != 0:
            # Non-zero exit code is not always an application error (e.g., ls non_existent_dir)
            # but we print it for informative purposes.
            print(f"'ls' command exited with code: {result.returncode}", file=sys.stderr)

    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)

def main():
    """Main function with test cases."""
    print("--- Test Case 1: Simple 'ls .' ---")
    cmd1 = create_command_string("{} {}", "ls", ".")
    print(f"Executing: {cmd1}")
    execute_ls_command(cmd1)
    print()

    print("--- Test Case 2: 'ls -l' with an option ---")
    cmd2 = create_command_string("{} {}", "ls", "-l")
    print(f"Executing: {cmd2}")
    execute_ls_command(cmd2)
    print()

    print("--- Test Case 3: 'ls' with a quoted argument (will be rejected by our validator) ---")
    # shlex would parse this to ['ls', 'a dir'], but our simple SAFE_ARG_PATTERN rejects 'a dir'.
    # This demonstrates a safe failure mode.
    cmd3 = create_command_string("{} '{}'", "ls", "a dir")
    print(f"Executing: {cmd3}")
    execute_ls_command(cmd3)
    print()

    print("--- Test Case 4: Malicious command injection attempt (should be blocked) ---")
    cmd4 = create_command_string("{} {}", "ls", ".;whoami")
    print(f"Executing: {cmd4}")
    execute_ls_command(cmd4)
    print()

    print("--- Test Case 5: Different command attempt (should be blocked) ---")
    cmd5 = create_command_string("{}", "whoami")
    print(f"Executing: {cmd5}")
    execute_ls_command(cmd5)
    print()
    
if __name__ == "__main__":
    main()