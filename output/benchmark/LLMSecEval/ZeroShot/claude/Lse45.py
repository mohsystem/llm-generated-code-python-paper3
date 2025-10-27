
import os
from pathlib import Path

SAFE_DIRECTORY = "/var/safe_files/"

def read_file_from_safe_directory(filename):
    try:
        # Sanitize the filename to prevent path traversal attacks
        sanitized_filename = os.path.basename(filename)
        
        # Construct the full path within the safe directory
        safe_path = Path(SAFE_DIRECTORY).resolve()
        file_path = (safe_path / sanitized_filename).resolve()
        
        # Verify the file is still within the safe directory
        if not str(file_path).startswith(str(safe_path)):
            return "Error: Path traversal attempt detected"
        
        # Check if file exists
        if not file_path.exists():
            return "Error: File not found"
        
        # Read and return file content
        with open(file_path, 'r') as f:
            return f.read()
            
    except Exception as e:
        return f"Error: {str(e)}"

if __name__ == "__main__":
    # Test cases
    print("Test 1:", read_file_from_safe_directory("document.txt"))
    print("Test 2:", read_file_from_safe_directory("data.json"))
    print("Test 3:", read_file_from_safe_directory("../etc/passwd"))
    print("Test 4:", read_file_from_safe_directory("nonexistent.txt"))
    print("Test 5:", read_file_from_safe_directory("config.ini"))
