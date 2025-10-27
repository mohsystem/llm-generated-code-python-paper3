
import os
from pathlib import Path

def read_file_from_safe_directory(filename, safe_directory):
    try:
        # Normalize and resolve the safe directory path
        safe_path = Path(safe_directory).resolve()
        
        # Normalize and resolve the requested file path
        requested_path = (safe_path / filename).resolve()
        
        # Check if the requested path is within the safe directory
        if not str(requested_path).startswith(str(safe_path)):
            return "Error: Access denied - file is outside safe directory"
        
        # Check if file exists
        if not requested_path.exists():
            return "Error: File not found"
        
        # Read and return file content
        with open(requested_path, 'r') as f:
            return f.read()
            
    except Exception as e:
        return f"Error: {str(e)}"

if __name__ == "__main__":
    # Create a test safe directory and files
    safe_dir = "safe_directory"
    os.makedirs(safe_dir, exist_ok=True)
    
    with open(os.path.join(safe_dir, "test1.txt"), "w") as f:
        f.write("Content of test1")
    
    with open(os.path.join(safe_dir, "test2.txt"), "w") as f:
        f.write("Content of test2")
    
    # Test case 1: Valid file in safe directory
    print("Test 1:", read_file_from_safe_directory("test1.txt", safe_dir))
    
    # Test case 2: Another valid file
    print("Test 2:", read_file_from_safe_directory("test2.txt", safe_dir))
    
    # Test case 3: Non-existent file
    print("Test 3:", read_file_from_safe_directory("nonexistent.txt", safe_dir))
    
    # Test case 4: Path traversal attempt
    print("Test 4:", read_file_from_safe_directory("../test.txt", safe_dir))
    
    # Test case 5: Another path traversal attempt
    print("Test 5:", read_file_from_safe_directory("../../etc/passwd", safe_dir))
