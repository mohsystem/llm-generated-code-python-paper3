import subprocess
import shlex

# 1. Validation: Use an allowlist of safe commands.
ALLOWED_COMMANDS = {"ls", "echo", "date", "pwd", "whoami"}

def execute_command(command: str) -> str:
    """
    Validates, executes a shell command, and returns its output.
    The command is validated against a strict allowlist.
    It uses shlex.split and subprocess.run to prevent command injection.
    
    :param command: The command string to execute (e.g., "ls -l").
    :return: The standard output and standard error from the command, or an error message.
    """
    if not command or not command.strip():
        return "Error: Command cannot be null or empty."

    try:
        # 2. Secure Parsing: shlex.split correctly handles arguments and quotes
        # and prevents shell metacharacter interpretation.
        command_parts = shlex.split(command)
    except ValueError as e:
        return f"Error: Invalid command format. {e}"
        
    if not command_parts:
        return "Error: Command is empty after parsing."

    base_command = command_parts[0]

    # 3. Validation against Allowlist
    if base_command not in ALLOWED_COMMANDS:
        return f"Error: Command '{base_command}' is not allowed."

    try:
        # 4. Secure Execution: Executing the list of arguments directly
        # avoids shell injection.
        # capture_output=True captures stdout and stderr.
        # text=True decodes them as strings.
        # timeout=10 prevents long-running commands.
        result = subprocess.run(
            command_parts,
            capture_output=True,
            text=True,
            check=False, # Do not raise exception on non-zero exit codes
            timeout=10
        )
        
        # 5. Combine stdout and stderr for full output
        output = result.stdout
        if result.stderr:
            output += "\n--- STDERR ---\n" + result.stderr

        if result.returncode != 0:
            output += f"\nCommand exited with non-zero status: {result.returncode}"
            
        return output

    except FileNotFoundError:
        return f"Error: Command not found: '{base_command}'."
    except subprocess.TimeoutExpired:
        return "Error: Command timed out."
    except Exception as e:
        return f"An unexpected error occurred: {e}"

def main():
    # --- Test Cases ---
    
    # Test Case 1: Valid and allowed command
    print("--- Test Case 1: ls -l ---")
    test1 = "ls -l"
    print(f"Executing: {test1}")
    print(f"Result:\n{execute_command(test1)}")

    # Test Case 2: Valid command with arguments
    print("--- Test Case 2: echo 'Hello Secure World' ---")
    test2 = "echo 'Hello Secure World'"
    print(f"Executing: {test2}")
    print(f"Result:\n{execute_command(test2)}")

    # Test Case 3: Disallowed command (potential for harm)
    print("--- Test Case 3: rm -rf / ---")
    test3 = "rm -rf /"
    print(f"Executing: {test3}")
    print(f"Result:\n{execute_command(test3)}")
    
    # Test Case 4: Command with shell metacharacters (attempted injection)
    print("--- Test Case 4: ls; whoami ---")
    test4 = "ls; whoami"
    print(f"Executing: {test4}")
    # shlex.split will treat 'ls;' as one argument, which won't be found
    print(f"Result:\n{execute_command(test4)}")

    # Test Case 5: Empty command
    print("--- Test Case 5: Empty Command ---")
    test5 = " "
    print("Executing: \" \"")
    print(f"Result:\n{execute_command(test5)}")


if __name__ == "__main__":
    main()