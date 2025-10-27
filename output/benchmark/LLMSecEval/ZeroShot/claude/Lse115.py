
import os
import subprocess
from pathlib import Path

def list_directory(directory_path):
    """\n    Secure method to list directory contents without shell injection risks\n    """
    try:
        # Validate and convert to Path object
        path = Path(directory_path)
        
        # Check if directory exists and is a directory
        if not path.exists() or not path.is_dir():
            return "Invalid directory path"
        
        # Use os.listdir for safe directory listing
        files = os.listdir(path)
        return "\\n".join(files)
    except Exception as e:
        return f"Error: {str(e)}"

def execute_list_command(directory_path):
    """\n    Alternative method using subprocess with proper argument separation\n    """
    try:
        # Validate directory path
        path = Path(directory_path)
        if not path.exists() or not path.is_dir():
            return "Invalid directory path"
        
        # Use subprocess with list of arguments (prevents injection)
        result = subprocess.run(
            ["ls", "-l", str(path)],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        return result.stdout if result.returncode == 0 else result.stderr
    except FileNotFoundError:
        return "ls command not found (Windows system?)"
    except Exception as e:
        return f"Error executing command: {str(e)}"

def main():
    print("Test Case 1: Current directory")
    print(list_directory("."))
    
    print("\\nTest Case 2: Home directory")
    print(list_directory(os.path.expanduser("~")))
    
    print("\\nTest Case 3: Root directory")
    print(list_directory("/"))
    
    print("\\nTest Case 4: Invalid directory")
    print(list_directory("/nonexistent/path"))
    
    print("\\nTest Case 5: Temp directory")
    print(list_directory("/tmp"))

if __name__ == "__main__":
    main()
