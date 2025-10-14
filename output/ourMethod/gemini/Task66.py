import subprocess
import shlex
from typing import List, Set

# A set of allowed commands to prevent execution of arbitrary programs.
ALLOWED_COMMANDS: Set[str] = {"ls", "echo", "date", "whoami"}


def execute_command(command: str) -> str:
    """
    Validates and executes a shell command securely.

    Args:
        command: The command string to execute.

    Returns:
        The combined standard output and standard error from the command.
    """
    if not command or not command.strip():
        return "Error: Command cannot be null or empty."

    try:
        # shlex.split is used to safely parse the command string,
        # handling quotes and preventing shell injection.
        command_parts: List[str] = shlex.split(command)
    except ValueError as e:
        return f"Error: Invalid command format. {e}"

    if not command_parts:
        return "Error: Command is empty."

    # Validate that the command is in the allowlist.
    program = command_parts[0]
    if program not in ALLOWED_COMMANDS:
        return f"Error: Command '{program}' is not allowed."

    try:
        # Execute the command without a shell.
        # `shell=False` is the default and is crucial for security.
        # The command and its arguments are passed as a list.
        result = subprocess.run(
            command_parts,
            capture_output=True,
            text=True,
            check=False  # Do not raise exception on non-zero exit codes
        )

        output = ""
        if result.stdout:
            output += result.stdout
        if result.stderr:
            output += f"stderr:\n{result.stderr}"
        
        output += f"Exited with code: {result.returncode}"
        return output

    except FileNotFoundError:
        return f"Error: Command not found: '{program}'."
    except Exception as e:
        return f"Error executing command: {e}"


def main():
    """Main function with test cases."""
    test_commands = [
        "ls -l",
        "echo 'hello from python'", # shlex handles quotes
        "grep root /etc/passwd", # Not in allowlist
        "ls; whoami",            # shlex splits this safely, but ; is not a command
        ""                       # Empty command
    ]

    for cmd in test_commands:
        print(f'Executing command: "{cmd}"')
        result = execute_command(cmd)
        print(f"Result:\n{result}")
        print("------------------------------------")


if __name__ == "__main__":
    main()