
import os
from pathlib import Path

def read_file_from_safe_directory(filename):
    try:
        # Define the safe directory
        safe_dir = Path("/safe/").resolve()
        
        # Construct the file path
        file_path = (safe_dir / filename).resolve()
        
        # Security check: ensure the resolved path is within safe directory
        if not str(file_path).startswith(str(safe_dir)):
            return "Error: Access denied - path traversal detected"
        
        # Check if file exists and is readable
        if not file_path.exists() or not file_path.is_file():
            return "Error: File does not exist or is not a regular file"
        
        # Read the file content
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        return content
        
    except PermissionError:
        return "Error: Permission denied"
    except IOError:
        return "Error: Unable to read file"
    except Exception:
        return "Error: An unexpected error occurred"

if __name__ == "__main__":
    # Test case 1: Normal file
    print("Test 1 - Normal file:")
    print(read_file_from_safe_directory("test.txt"))
    
    # Test case 2: Path traversal attempt
    print("\\nTest 2 - Path traversal attempt:")
    print(read_file_from_safe_directory("../etc/passwd"))
    
    # Test case 3: Another path traversal
    print("\\nTest 3 - Another traversal:")
    print(read_file_from_safe_directory("../../secret.txt"))
    
    # Test case 4: Subdirectory file
    print("\\nTest 4 - Subdirectory:")
    print(read_file_from_safe_directory("subdir/file.txt"))
    
    # Test case 5: Non-existent file
    print("\\nTest 5 - Non-existent file:")
    print(read_file_from_safe_directory("nonexistent.txt"))
