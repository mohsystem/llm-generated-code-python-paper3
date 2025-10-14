import subprocess
import shlex
import signal
from typing import Optional

class Task66:
    ALLOWED_COMMANDS = {'ls', 'pwd', 'date', 'whoami', 'echo'}
    TIMEOUT_SECONDS = 5
    MAX_OUTPUT_LENGTH = 10000

    @staticmethod
    def execute_command(user_input: str) -> str:
        if not user_input or not user_input.strip():
            return "Error: Command cannot be empty"

        user_input = user_input.strip()

        # Validate: no dangerous characters
        forbidden_chars = [';', '&', '|', '>', '<', '`', '$', '\\', '\n', '\r']
        if any(char in user_input for char in forbidden_chars):
            return "Error: Command contains forbidden characters"

        # Parse command and arguments safely
        try:
            parts = shlex.split(user_input)
        except ValueError as e:
            return f"Error: Invalid command format - {str(e)}"

        if not parts:
            return "Error: No command provided"

        command = parts[0]

        # Whitelist validation
        if command not in Task66.ALLOWED_COMMANDS:
            return f"Error: Command '{command}' is not in the allowed list"

        try:
            # Execute with timeout and capture output
            result = subprocess.run(
                parts,
                capture_output=True,
                text=True,
                timeout=Task66.TIMEOUT_SECONDS,
                shell=False  # Critical: Never use shell=True
            )

            output = result.stdout + result.stderr

            # Limit output length
            if len(output) > Task66.MAX_OUTPUT_LENGTH:
                output = output[:Task66.MAX_OUTPUT_LENGTH] + "\n[Output truncated]"

            if not output:
                return "Command executed successfully (no output)"

            return output

        except subprocess.TimeoutExpired:
            return "Error: Command execution timeout"
        except FileNotFoundError:
            return f"Error: Command '{command}' not found"
        except Exception as e:
            return f"Error: {str(e)}"

    @staticmethod
    def main():
        print("=== Secure Command Executor Test Cases ===")

        test_cases = [
            "ls",
            "pwd",
            "echo Hello World",
            "ls; rm -rf /",  # Malicious attempt
            "cat /etc/passwd"  # Unauthorized command
        ]

        for i, test in enumerate(test_cases, 1):
            print(f"Test Case {i}: {test}")
            print(f"Result: {Task66.execute_command(test)}")
            print("---")

if __name__ == "__main__":
    Task66.main()
