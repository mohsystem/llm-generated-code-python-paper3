
import os
from pathlib import Path

SAFE_DIRECTORY = "/safe/"

def read_safe_file(filename):
    if not filename or not filename.strip():
        return "Error: Filename cannot be empty"
    
    try:
        # Get absolute canonical path of safe directory
        safe_path = os.path.realpath(SAFE_DIRECTORY)
        
        # Construct and resolve the requested file path
        requested_path = os.path.realpath(os.path.join(safe_path, filename))
        
        # Verify the resolved path is within safe directory
        if not requested_path.startswith(safe_path + os.sep) and requested_path != safe_path:
            return "Error: Access denied - file outside safe directory"
        
        # Check if file exists and is readable
        if not os.path.exists(requested_path) or not os.path.isfile(requested_path):
            return "Error: File not found or not readable"
        
        # Read file content
        with open(requested_path, 'r', encoding='utf-8') as file:
            return file.read()
            
    except Exception as e:
        return "Error: Unable to read file"

def main():
    # Test cases
    print("Test 1 - Normal file:")
    print(read_safe_file("test.txt"))
    
    print("\\nTest 2 - Path traversal attempt:")
    print(read_safe_file("../etc/passwd"))
    
    print("\\nTest 3 - Empty filename:")
    print(read_safe_file(""))
    
    print("\\nTest 4 - None filename:")
    print(read_safe_file(None))
    
    print("\\nTest 5 - Non-existent file:")
    print(read_safe_file("nonexistent.txt"))

if __name__ == "__main__":
    main()
