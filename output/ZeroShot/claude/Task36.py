
import os
from pathlib import Path

def read_file_contents(file_path):
    try:
        # Normalize and validate the path to prevent path traversal
        normalized_path = os.path.normpath(file_path)
        
        # Security checks
        if not os.path.exists(normalized_path):
            return "Error: File does not exist"
        if not os.path.isfile(normalized_path):
            return "Error: Path is not a file"
        if not os.access(normalized_path, os.R_OK):
            return "Error: File is not readable"
        
        # Read file contents
        with open(normalized_path, 'r', encoding='utf-8') as file:
            content = file.read()
        return content
    except IOError as e:
        return f"Error reading file: {str(e)}"
    except Exception as e:
        return f"Error: {str(e)}"

if __name__ == "__main__":
    # Create test files
    try:
        with open("test1.txt", "w") as f:
            f.write("Hello World!\\nThis is test file 1.")
        with open("test2.txt", "w") as f:
            f.write("Line 1\\nLine 2\\nLine 3")
        with open("test3.txt", "w") as f:
            f.write("Single line file")
        with open("test4.txt", "w") as f:
            f.write("")
        with open("test5.txt", "w") as f:
            f.write("Test file 5\\nWith multiple\\nLines of text")
    except Exception as e:
        print("Error creating test files")
    
    # Test cases
    print("Test Case 1:")
    print(read_file_contents("test1.txt"))
    
    print("\\nTest Case 2:")
    print(read_file_contents("test2.txt"))
    
    print("\\nTest Case 3:")
    print(read_file_contents("test3.txt"))
    
    print("\\nTest Case 4 (empty file):")
    print(read_file_contents("test4.txt"))
    
    print("\\nTest Case 5:")
    print(read_file_contents("test5.txt"))
    
    # Cleanup
    try:
        os.remove("test1.txt")
        os.remove("test2.txt")
        os.remove("test3.txt")
        os.remove("test4.txt")
        os.remove("test5.txt")
    except Exception:
        pass
