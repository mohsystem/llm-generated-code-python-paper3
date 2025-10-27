import os
import shlex
import sys

def execute_ls_command(path: str, flags: str):
    """
    Constructs and executes an 'ls' command.

    Args:
        path: The directory path to list.
        flags: The flags to pass to the 'ls' command (e.g., "-l").
    """
    # Rule #1 & #2: Sanitize inputs before passing them to a dangerous function.
    # shlex.quote is the standard, secure way in Python to escape strings
    # for safe inclusion in a shell command.
    safe_path = shlex.quote(path)
    
    # The 'print function' (an f-string) is used to create the string 
    # that is passed to the system function.
    command_parts = ["ls"]
    if flags:
        # Also quote flags to be safe, although in this example they are hardcoded.
        safe_flags = shlex.quote(flags)
        command_parts.append(safe_flags)
    command_parts.append(safe_path)
    
    command = " ".join(command_parts)

    print(f"Executing command: {command}")
    print("---")
    
    # Rule #2: os.system executes the command in a subshell, which is a
    # known security risk if inputs are not sanitized. Here, we use it
    # with properly quoted arguments. The safer alternative is to use
    # subprocess.run(['ls', flags, path]) which avoids the shell entirely.
    exit_code = os.system(command)
    
    print("---")
    # The exit code from os.system is system-dependent. On Unix, we need to shift.
    final_exit_code = exit_code >> 8 if os.name != 'nt' else exit_code
    print(f"Command finished with exit code: {final_exit_code}")

def main():
    """Main function with test cases."""
    print("--- Test Case 1: List current directory ---")
    execute_ls_command(".", "")

    print("\n--- Test Case 2: List /tmp with long format ---")
    execute_ls_command("/tmp", "-l")
    
    print("\n--- Test Case 3: Path with spaces (safely quoted) ---")
    # This will fail on systems without a directory with this exact name,
    # but it demonstrates that the quoting works correctly.
    execute_ls_command("a directory with spaces", "-a")

    print("\n--- Test Case 4: Malicious path (properly quoted and thus safe) ---")
    # The shell will treat "; ls" as part of the filename, not a new command.
    execute_ls_command(".; ls", "")
    
    print("\n--- Test Case 5: Malicious flag (properly quoted and thus safe) ---")
    # The shell will pass "-l; echo vulnerable" as a single, literal argument to 'ls'.
    execute_ls_command(".", "-l; echo vulnerable")

if __name__ == "__main__":
    main()