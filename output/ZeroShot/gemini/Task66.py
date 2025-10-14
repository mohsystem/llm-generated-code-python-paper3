import subprocess
import shlex

# 1. A whitelist of allowed commands is the most effective security measure.
ALLOWED_COMMANDS = {"ls", "pwd", "date", "echo"}

def execute_secure_command(command: str) -> str:
    """
    Executes a command securely after validation.
    :param command: The command string to execute.
    :return: The output of the command or an error message.
    """
    if not command or not command.strip():
        return "Error: Command cannot be null or empty."

    try:
        # Use shlex to safely split the command string, respecting quotes.
        parts = shlex.split(command)
    except ValueError as e:
        return f"Error: Malformed command string. {e}"

    if not parts:
        return "Error: Command is empty after parsing."

    base_command = parts[0]

    # 2. Validate command against the allowlist.
    if base_command not in ALLOWED_COMMANDS:
        return f"Error: Command '{base_command}' is not allowed."

    # 3. Validate arguments for insecure patterns.
    for arg in parts[1:]:
        # Disallow path traversal and common shell metacharacters.
        if ".." in arg or any(char in arg for char in ";&|<>`$()\\{\\}"):
            return f"Error: Argument '{arg}' contains forbidden characters or patterns."

    try:
        # 4. Execute the command without a shell (shell=False is default and secure).
        # Add a timeout to prevent resource exhaustion attacks.
        result = subprocess.run(
            parts,
            capture_output=True,
            text=True,
            check=False,  # We check the return code manually to provide better error messages.
            timeout=5
        )
        
        # Combine stdout and stderr for the final output
        output = ""
        if result.stdout:
            output += result.stdout
        if result.stderr:
            output += result.stderr

        if result.returncode != 0:
            return f"Error: Command exited with code {result.returncode}.\nOutput:\n{output}"

        return output

    except FileNotFoundError:
        return f"Error: Command not found: {base_command}"
    except subprocess.TimeoutExpired:
        return "Error: Command timed out."
    except Exception as e:
        return f"An unexpected error occurred: {e}"

def main():
    test_commands = [
        "ls -l",                # 1. Valid command
        "echo 'Hello World'",   # 2. Valid command with quoted arguments
        "whoami",               # 3. Invalid command (not in allowlist)
        "ls; rm -rf /",         # 4. Injection attempt (shlex makes this 'ls;' 'rm' '-rf' '/' and 'ls;' is rejected)
        "ls ../../"             # 5. Path traversal attempt
    ]

    for cmd in test_commands:
        print(f"Executing: '{cmd}'")
        print("-------------------------")
        result = execute_secure_command(cmd)
        print(f"Result:\n{result}")
        print("=========================")

if __name__ == "__main__":
    main()