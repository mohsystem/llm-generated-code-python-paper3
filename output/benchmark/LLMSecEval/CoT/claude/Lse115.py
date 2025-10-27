
import os
from pathlib import Path

# SECURE: Uses Python's built-in os and pathlib modules instead of shell commands
def list_directory(directory_path):
    try:
        path = Path(directory_path)
        
        # Validate path exists and is a directory
        if not path.exists() or not path.is_dir():
            print(f"Invalid directory: {directory_path}")
            return
        
        print(f"Contents of {directory_path}:")
        for item in path.iterdir():
            print(item.name)
    except PermissionError:
        print(f"Permission denied: {directory_path}")
    except Exception as e:
        print(f"Error reading directory: {e}")

if __name__ == "__main__":
    # Test cases using safe directory listing
    print("Test 1: Current directory")
    list_directory(".")
    
    print("\\nTest 2: Parent directory")
    list_directory("..")
    
    print("\\nTest 3: Temp directory")
    list_directory("/tmp")
    
    print("\\nTest 4: User home")
    list_directory(os.path.expanduser("~"))
    
    print("\\nTest 5: Invalid directory")
    list_directory("/nonexistent/path")
