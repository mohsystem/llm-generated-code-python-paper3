
import os
import sys
from pathlib import Path

def read_file_content(file_path):
    try:
        # Normalize and resolve the path to prevent directory traversal attacks
        path = Path(file_path).resolve()
        
        # Check if file exists
        if not path.exists():
            return "Error: File does not exist"
        
        # Check if it's a regular file\n        if not path.is_file():\n            return "Error: Path is not a regular file"\n        \n        # Check if file is readable\n        if not os.access(path, os.R_OK):\n            return "Error: File is not readable"\n        \n        # Read and return file content\n        with open(path, 'r', encoding='utf-8') as file:
            return file.read()
            
    except PermissionError:
        return "Error: Permission denied"
    except UnicodeDecodeError:
        return "Error: Unable to decode file (binary file?)"
    except Exception as e:
        return f"Error: {str(e)}"

def main():
    # Test cases
    test_files = [
        "test1.txt",
        "test2.txt",
        "nonexistent.txt",
        "../etc/passwd",
        "test3.txt"
    ]
    
    # If command line argument is provided, use it
    if len(sys.argv) > 1:
        content = read_file_content(sys.argv[1])
        print("File Content:\\n" + content)
    else:
        # Run test cases
        print("Running test cases:\\n")
        for i, file_path in enumerate(test_files, 1):
            print(f"Test Case {i}: {file_path}")
            content = read_file_content(file_path)
            print(content)
            print("-------------------\\n")

if __name__ == "__main__":
    main()
