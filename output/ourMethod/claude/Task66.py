
import subprocess
import re
from typing import Optional

ALLOWED_COMMANDS = {'echo', 'date', 'pwd', 'whoami', 'ls'}
SAFE_ARGUMENT_PATTERN = re.compile(r'^[a-zA-Z0-9._/\\-]+$')
MAX_COMMAND_LENGTH = 256
MAX_ARGUMENTS = 10

def execute_command(user_input: str) -> str:
    if not user_input or not user_input.strip():
        return "Error: Empty command"
    
    if len(user_input) > MAX_COMMAND_LENGTH:
        return "Error: Command too long"
    
    parts = user_input.strip().split()
    
    if len(parts) == 0:
        return "Error: Invalid command"
    
    if len(parts) > MAX_ARGUMENTS + 1:
        return "Error: Too many arguments"
    
    command = parts[0]
    
    if command not in ALLOWED_COMMANDS:
        return f"Error: Command not allowed. Allowed commands: {ALLOWED_COMMANDS}"
    
    for arg in parts[1:]:
        if not SAFE_ARGUMENT_PATTERN.match(arg):
            return "Error: Invalid characters in argument"
    
    try:
        result = subprocess.run(
            parts,
            capture_output=True,
            text=True,
            timeout=5,
            encoding='utf-8'
        )
        
        if result.returncode != 0:
            return f"Error: Command exited with code {result.returncode}\\n{result.stdout}{result.stderr}"
        
        return result.stdout
        
    except subprocess.TimeoutExpired:
        return "Error: Command timed out"
    except FileNotFoundError:
        return "Error: Command not found"
    except Exception as e:
        return f"Error: Failed to execute command: {type(e).__name__}"

def main():
    print("Test 1 - echo hello:")
    print(execute_command("echo hello"))
    
    print("\\nTest 2 - pwd:")
    print(execute_command("pwd"))
    
    print("\\nTest 3 - Invalid command (rm):")
    print(execute_command("rm file.txt"))
    
    print("\\nTest 4 - Invalid characters:")
    print(execute_command("echo $(whoami)"))
    
    print("\\nTest 5 - Empty command:")
    print(execute_command(""))

if __name__ == "__main__":
    main()
