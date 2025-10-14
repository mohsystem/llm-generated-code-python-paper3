
import subprocess
import re
import sys

SAFE_FILENAME_PATTERN = re.compile(r'^[a-zA-Z0-9._-]+$')
ALLOWED_COMMANDS = ['echo', 'date', 'whoami']

def execute_command(command, argument=""):
    """\n    Securely execute an OS command with user input\n    \n    Args:\n        command: The command to execute (must be in whitelist)\n        argument: The argument to pass to the command\n    \n    Returns:\n        String output of the command or error message\n    """
    try:
        # Validate command is in whitelist
        if command not in ALLOWED_COMMANDS:
            return f"Error: Command not allowed. Allowed commands: {ALLOWED_COMMANDS}"
        
        # Validate argument (no special characters for shell injection)
        if argument and not SAFE_FILENAME_PATTERN.match(argument):
            return "Error: Invalid argument. Only alphanumeric characters, dots, hyphens, and underscores allowed."
        
        # Build command list (prevents shell injection)
        if argument:
            cmd_list = [command, argument]
        else:
            cmd_list = [command]
        
        # Execute command safely without shell interpretation
        result = subprocess.run(
            cmd_list,
            capture_output=True,
            text=True,
            timeout=5,
            shell=False  # Critical: Never use shell=True with user input
        )
        
        if result.returncode != 0:
            return f"Command executed with exit code: {result.returncode}\\n{result.stdout}{result.stderr}"
        
        return result.stdout.strip()
        
    except subprocess.TimeoutExpired:
        return "Error: Command execution timeout"
    except Exception as e:
        return f"Error executing command: {str(e)}"

def main():
    print("=== Secure OS Command Execution Demo ===\\n")
    
    # Test Case 1: Valid echo command with safe argument
    print("Test 1 - Echo command:")
    print(execute_command("echo", "Hello_World"))
    print()
    
    # Test Case 2: Date command (no argument)
    print("Test 2 - Date command:")
    print(execute_command("date", ""))
    print()
    
    # Test Case 3: Invalid command (not in whitelist)
    print("Test 3 - Invalid command:")
    print(execute_command("rm", "file.txt"))
    print()
    
    # Test Case 4: Command injection attempt (should be blocked)
    print("Test 4 - Injection attempt:")
    print(execute_command("echo", "test; rm -rf /"))
    print()
    
    # Test Case 5: Whoami command
    print("Test 5 - Whoami command:")
    print(execute_command("whoami", ""))
    print()

if __name__ == "__main__":
    main()
