import subprocess
import re
import shlex

class Task66:
    ALLOWED_COMMANDS = {'ls', 'pwd', 'date', 'whoami', 'echo'}
    DANGEROUS_PATTERN = re.compile(r'.*[;&|`$(){}\[\]<>].*|.*\.\..*')

    @staticmethod
    def execute_command(command):
        if not command or not command.strip():
            return "Error: Command cannot be empty"

        command = command.strip()

        # Check for dangerous characters
        if Task66.DANGEROUS_PATTERN.match(command):
            return "Error: Command contains dangerous characters"

        # Parse command safely
        try:
            parts = shlex.split(command)
        except ValueError as e:
            return f"Error: Invalid command format - {str(e)}"

        if not parts:
            return "Error: Command cannot be empty"

        base_command = parts[0]

        # Validate against whitelist
        if base_command not in Task66.ALLOWED_COMMANDS:
            return f"Error: Command not allowed. Allowed commands: {Task66.ALLOWED_COMMANDS}"

        # Validate arguments
        for arg in parts[1:]:
            if '/' in arg or '\\' in arg:
                return "Error: Path traversal not allowed in arguments"

        # Execute command
        try:
            result = subprocess.run(
                parts,
                capture_output=True,
                text=True,
                timeout=5,
                check=False
            )

            if result.returncode != 0:
                return f"Error: Command exited with code {result.returncode}\n{result.stdout}{result.stderr}"

            return result.stdout.strip()

        except subprocess.TimeoutExpired:
            return "Error: Command execution timed out"
        except Exception as e:
            return f"Error executing command: {str(e)}"

def main():
    print("=== Test Case 1: Valid command 'pwd' ===")
    print(Task66.execute_command("pwd"))
    print()

    print("=== Test Case 2: Valid command 'date' ===")
    print(Task66.execute_command("date"))
    print()

    print("=== Test Case 3: Valid command 'echo' with arguments ===")
    print(Task66.execute_command("echo Hello World"))
    print()

    print("=== Test Case 4: Invalid command with dangerous characters ===")
    print(Task66.execute_command("ls; rm -rf /"))
    print()

    print("=== Test Case 5: Unauthorized command ===")
    print(Task66.execute_command("rm testfile.txt"))
    print()

if __name__ == "__main__":
    main()
