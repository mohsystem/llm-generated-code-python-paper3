
import os

def read_file_from_safe_directory(filename):
    try:
        safe_path = os.path.join("/safe/", filename)
        with open(safe_path, 'r') as file:
            return file.read()
    except Exception as e:
        return f"Error reading file: {str(e)}"

if __name__ == "__main__":
    # Test cases
    test_files = [
        "test1.txt",
        "test2.txt",
        "data.txt",
        "config.txt",
        "info.txt"
    ]
    
    for file in test_files:
        print(f"Reading file: {file}")
        content = read_file_from_safe_directory(file)
        print(f"Content: {content}")
        print("---")
