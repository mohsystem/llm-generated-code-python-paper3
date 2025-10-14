
import sys
import os

def read_file_content(file_path):
    try:
        with open(file_path, 'r') as file:
            return file.read()
    except FileNotFoundError:
        return f"Error reading file: File not found - {file_path}"
    except Exception as e:
        return f"Error reading file: {str(e)}"

if __name__ == "__main__":
    # Test cases
    test_files = [
        "test1.txt",
        "test2.txt",
        "test3.txt",
        "nonexistent.txt",
        "test5.txt"
    ]
    
    # Create test files
    try:
        with open("test1.txt", "w") as f:
            f.write("Hello, World!")
        with open("test2.txt", "w") as f:
            f.write("Python Programming")
        with open("test3.txt", "w") as f:
            f.write("File I/O Operations")
        with open("test5.txt", "w") as f:
            f.write("Test Case 5")
    except Exception as e:
        print("Error creating test files")
    
    # If command line argument provided, use it
    if len(sys.argv) > 1:
        content = read_file_content(sys.argv[1])
        print("File Content:")
        print(content)
    else:
        # Run test cases
        print("Running test cases:\\n")
        for i, test_file in enumerate(test_files, 1):
            print(f"Test Case {i}: {test_file}")
            content = read_file_content(test_file)
            print(f"Content: {content}")
            print("---")
