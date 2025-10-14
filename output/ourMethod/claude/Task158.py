
import subprocess
import re
from typing import Optional

SAFE_INPUT_PATTERN = re.compile(r'^[a-zA-Z0-9_.-]+$')
MAX_INPUT_LENGTH = 100
ALLOWED_COMMANDS = ['echo', 'date', 'whoami']

def execute_command(command: str, user_input: str) -> str:
    """\n    Execute a whitelisted OS command with validated user input.\n    \n    Args:\n        command: The command to execute (must be in whitelist)\n        user_input: User-provided input (validated against pattern)\n    \n    Returns:\n        Command output or error message\n    """
    if command is None or user_input is None:
        return "Error: Null input not allowed"
    
    if not command.strip() or not user_input.strip():
        return "Error: Empty input not allowed"
    
    if command not in ALLOWED_COMMANDS:
        return "Error: Command not in whitelist"
    
    if len(user_input) > MAX_INPUT_LENGTH:
        return "Error: Input exceeds maximum length"
    
    if not SAFE_INPUT_PATTERN.match(user_input):
        return "Error: Input contains invalid characters"
    
    try:
        result = subprocess.run(
            [command, user_input],
            capture_output=True,
            text=True,
            timeout=5,
            check=False
        )
        
        if result.returncode != 0:
            return f"Error: Command failed with exit code {result.returncode}"
        
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return "Error: Command timeout"
    except Exception as e:
        return f"Error: {type(e).__name__}"

def main():
    print("Test 1 - Valid echo command:")
    print(execute_command("echo", "test123"))
    
    print("\\nTest 2 - Valid input with dots:")
    print(execute_command("echo", "file.txt"))
    
    print("\\nTest 3 - Invalid command injection attempt:")
    print(execute_command("echo", "test;ls"))
    
    print("\\nTest 4 - Command not in whitelist:")
    print(execute_command("rm", "file.txt"))
    
    print("\\nTest 5 - Input too long:")
    print(execute_command("echo", "a" * 101))

if __name__ == "__main__":
    main()
