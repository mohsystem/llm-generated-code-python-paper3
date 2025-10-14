
import subprocess
import re
import sys

def execute_command(command):
    if not command or not command.strip():
        return "Error: Command cannot be empty"
    
    # Validate command format
    if not validate_command(command):
        return "Error: Invalid or potentially dangerous command"
    
    try:
        result = subprocess.run(
            command,
            shell=True,
            executable='/bin/bash',
            capture_output=True,
            text=True,
            timeout=30
        )
        
        output = result.stdout
        if result.stderr:
            output += result.stderr
            
        if not output and result.returncode != 0:
            output = f"Command executed with exit code: {result.returncode}"
            
        return output.strip()
        
    except subprocess.TimeoutExpired:
        return "Error: Command execution timeout"
    except Exception as e:
        return f"Error executing command: {str(e)}"

def validate_command(command):
    # Basic validation - reject potentially dangerous commands
    dangerous_patterns = [
        r'rm\\s+-rf\\s+/',
        r':\\(\\)\\{.*:\\|:&\\}',  # fork bomb
        r'dd\\s+if=',
        r'mkfs',
        r'format',
        r'>\\s*/dev/sda'
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, command):
            return False
    
    return True

if __name__ == "__main__":
    print("Test Case 1: echo 'Hello World'")
    print(execute_command("echo 'Hello World'"))
    print()
    
    print("Test Case 2: ls -la | head -5")
    print(execute_command("ls -la | head -5"))
    print()
    
    print("Test Case 3: date")
    print(execute_command("date"))
    print()
    
    print("Test Case 4: pwd")
    print(execute_command("pwd"))
    print()
    
    print("Test Case 5: echo $((5 + 3))")
    print(execute_command("echo $((5 + 3))"))
    print()
