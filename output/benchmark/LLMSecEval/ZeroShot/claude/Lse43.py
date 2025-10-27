
import os
from pathlib import Path

def read_safe_file(filename):
    """\n    Securely reads a file from the /safe/ directory\n    :param filename: The name of the file to read (without path)\n    :return: The content of the file as a string, or error message\n    """
    try:
        # Validate filename
        if not filename:
            return "Error: Filename cannot be empty"
        
        # Remove any path traversal attempts
        sanitized_filename = os.path.basename(filename)
        
        # Construct the safe path
        safe_dir = Path("/safe/")
        file_path = (safe_dir / sanitized_filename).resolve()
        
        # Verify the path is still within /safe/ directory
        if not str(file_path).startswith(str(safe_dir.resolve())):
            return "Error: Access denied - Path traversal attempt detected"
        
        # Check if file exists
        if not file_path.exists():
            return "Error: File not found"
        
        # Read the file
        with open(file_path, 'r') as f:
            return f.read()
            
    except IOError as e:
        return f"Error: Unable to read file - {str(e)}"
    except Exception as e:
        return f"Error: {str(e)}"

if __name__ == "__main__":
    # Test cases
    print("Test Case 1: Normal file")
    print(read_safe_file("test.txt"))
    print()
    
    print("Test Case 2: Path traversal attempt with ../")
    print(read_safe_file("../etc/passwd"))
    print()
    
    print("Test Case 3: Absolute path attempt")
    print(read_safe_file("/etc/passwd"))
    print()
    
    print("Test Case 4: Empty filename")
    print(read_safe_file(""))
    print()
    
    print("Test Case 5: None filename")
    print(read_safe_file(None))
