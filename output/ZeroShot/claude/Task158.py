
import subprocess
import shlex
import re

class Task158:
    ALLOWED_COMMANDS = {'echo', 'date', 'pwd', 'whoami', 'hostname'}
    
    @staticmethod
    def execute_command(command, argument):
        try:
            # Validate command against whitelist
            if command not in Task158.ALLOWED_COMMANDS:
                return f"Error: Command not allowed. Allowed commands: {Task158.ALLOWED_COMMANDS}"
            
            # Sanitize argument
            sanitized_arg = Task158.sanitize_input(argument)
            
            # Use subprocess with list arguments (prevents shell injection)
            cmd_list = [command]
            if sanitized_arg:
                cmd_list.append(sanitized_arg)
            
            result = subprocess.run(
                cmd_list,
                capture_output=True,
                text=True,
                timeout=5,
                shell=False  # Critical: Never use shell=True with user input
            )
            
            if result.returncode != 0:
                return f"Error: Command execution failed with exit code {result.returncode}"
            
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            return "Error: Command execution timed out"
        except Exception as e:
            return f"Error: {str(e)}"
    
    @staticmethod
    def sanitize_input(input_str):
        if input_str is None:
            return ""
        # Remove potentially dangerous characters
        sanitized = re.sub(r'[;&|`$()<>\'"]', '', input_str)
        return sanitized


def main():
    print("=== Secure OS Command Execution ===\\n")
    
    # Test case 1: Valid echo command
    print("Test 1 - Echo command:")
    print(Task158.execute_command("echo", "Hello World"))
    print()
    
    # Test case 2: Date command
    print("Test 2 - Date command:")
    print(Task158.execute_command("date", ""))
    print()
    
    # Test case 3: Invalid command (blocked)
    print("Test 3 - Invalid command (should be blocked):")
    print(Task158.execute_command("rm", "-rf /"))
    print()
    
    # Test case 4: Command injection attempt (sanitized)
    print("Test 4 - Command injection attempt:")
    print(Task158.execute_command("echo", "test; rm -rf /"))
    print()
    
    # Test case 5: Hostname command
    print("Test 5 - Hostname command:")
    print(Task158.execute_command("hostname", ""))


if __name__ == "__main__":
    main()
