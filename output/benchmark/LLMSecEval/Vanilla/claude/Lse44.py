
import os

def read_file_from_safe_directory(filename):
    try:
        # Construct the safe directory path
        safe_directory = "/safe/"
        file_path = os.path.normpath(os.path.join(safe_directory, filename))
        
        # Security check: ensure the resolved path is still within /safe/
        if not file_path.startswith("/safe/"):
            return "Error: Access denied - path traversal attempt detected"
        
        # Read the file content
        with open(file_path, 'r') as file:
            content = file.read()
        return content
    except Exception as e:
        return f"Error reading file: {str(e)}"

if __name__ == "__main__":
    # Test cases
    print("Test Case 1: Reading 'document.txt'")
    print(read_file_from_safe_directory("document.txt"))
    
    print("\\nTest Case 2: Reading 'data.txt'")
    print(read_file_from_safe_directory("data.txt"))
    
    print("\\nTest Case 3: Path traversal attempt '../etc/passwd'")
    print(read_file_from_safe_directory("../etc/passwd"))
    
    print("\\nTest Case 4: Reading subdirectory file 'subdir/file.txt'")
    print(read_file_from_safe_directory("subdir/file.txt"))
    
    print("\\nTest Case 5: Non-existent file 'nonexistent.txt'")
    print(read_file_from_safe_directory("nonexistent.txt"))
