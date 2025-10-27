
import os
from pathlib import Path
import sys

# SECURE ALTERNATIVE: Use Python's os module instead of system commands
def list_directory_secure(directory_path):
    """\n    Securely list directory contents without system calls\n    """
    try:
        path = Path(directory_path)
        
        # Validate path exists and is a directory
        if not path.exists() or not path.is_dir():
            print(f"Invalid directory path: {directory_path}")
            return
        
        # Securely list directory contents
        for item in path.iterdir():
            print(item.name)
            
    except PermissionError:
        print(f"Permission denied: {directory_path}")
    except Exception as e:
        print(f"Error accessing directory: {e}")

# WARNING: INSECURE - For educational purposes only
# DO NOT USE IN PRODUCTION
def list_directory_unsafe(directory):
    """\n    INSECURE: Vulnerable to command injection\n    This function is intentionally not implemented\n    """
    print("WARNING: system() calls are insecure and should never be used")
    # Intentionally not implementing: os.system(f"ls {directory}")
    pass

def main():
    print("=== Secure Directory Listing ===\\n")
    
    # Test case 1: Current directory
    print("Test 1 - Current directory:")
    list_directory_secure(".")
    
    # Test case 2: Parent directory
    print("\\nTest 2 - Parent directory:")
    list_directory_secure("..")
    
    # Test case 3: Temp directory
    print("\\nTest 3 - Temp directory:")
    list_directory_secure("/tmp")
    
    # Test case 4: Invalid path
    print("\\nTest 4 - Invalid path:")
    list_directory_secure("/nonexistent/path")
    
    # Test case 5: Home directory
    print("\\nTest 5 - Home directory:")
    list_directory_secure(str(Path.home()))

if __name__ == "__main__":
    main()
