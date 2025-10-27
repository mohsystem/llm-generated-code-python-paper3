
import os
from pathlib import Path

SAFE_DIRECTORY = "/safe/"

def read_file_from_safe_directory(requested_file):
    try:
        # Normalize and resolve the path
        safe_path = Path(SAFE_DIRECTORY).resolve()
        requested_path = (safe_path / requested_file).resolve()
        
        # Security check: ensure the resolved path is still within the safe directory
        if not str(requested_path).startswith(str(safe_path)):
            return "Error: Access denied - Path traversal attempt detected"
        
        # Check if file exists
        if not requested_path.exists():
            return "Error: File not found"
        
        # Read and return file content
        with open(requested_path, 'r', encoding='utf-8') as file:
            return file.read()
            
    except Exception as e:
        return f"Error: Unable to read file - {str(e)}"

if __name__ == "__main__":
    # Test cases
    print("Test 1 - Normal file:")
    print(read_file_from_safe_directory("test.txt"))
    
    print("\\nTest 2 - Path traversal attempt:")
    print(read_file_from_safe_directory("../../../etc/passwd"))
    
    print("\\nTest 3 - Another path traversal:")
    print(read_file_from_safe_directory("..\\\\..\\\\windows\\\\system32\\\\config\\\\sam"))
    
    print("\\nTest 4 - Non-existent file:")
    print(read_file_from_safe_directory("nonexistent.txt"))
    
    print("\\nTest 5 - Subdirectory file:")
    print(read_file_from_safe_directory("subdir/file.txt"))
