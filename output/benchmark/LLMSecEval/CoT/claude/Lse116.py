
# Python - Secure alternative using subprocess with argument list
import subprocess
import os

def execute_list_command(directory):
    """\n    SECURE: Uses subprocess with argument list to prevent command injection\n    """
    try:
        # Validate directory path
        if directory is None or '..' in directory or ';' in directory or '|' in directory:
            return "Error: Invalid directory path"
        
        # Use subprocess with argument list (NOT shell=True)
        # This prevents command injection
        if os.name == 'nt':  # Windows
            result = subprocess.run(['cmd', '/c', 'dir', directory], 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=5)
        else:  # Unix/Linux/Mac
            result = subprocess.run(['ls', '-l', directory], 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=5)
        
        return result.stdout if result.returncode == 0 else f"Error: {result.stderr}"
        
    except subprocess.TimeoutExpired:
        return "Error: Command timeout"
    except Exception as e:
        return f"Error executing command: {str(e)}"

def main():
    print("Test Case 1: Current directory")
    print(execute_list_command("."))
    
    print("\\nTest Case 2: Root directory")
    print(execute_list_command("/"))
    
    print("\\nTest Case 3: Home directory")
    print(execute_list_command(os.path.expanduser("~")))
    
    print("\\nTest Case 4: Invalid path with traversal attempt")
    print(execute_list_command("../../../etc"))
    
    print("\\nTest Case 5: Command injection attempt")
    print(execute_list_command("; rm -rf /"))

if __name__ == "__main__":
    main()
