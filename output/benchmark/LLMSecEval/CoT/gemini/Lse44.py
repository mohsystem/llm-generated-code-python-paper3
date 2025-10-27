import os

SAFE_DIRECTORY = "/safe/"

def read_file(filename: str) -> str:
    """
    Reads a file from the predefined SAFE_DIRECTORY, preventing path traversal.

    :param filename: The name of the file to read.
    :return: The content of the file as a string, or an error message.
    """
    if not filename or ".." in filename or "/" in filename or "\\" in filename:
        return "Error: Invalid filename provided."

    try:
        # Get absolute path of the safe directory
        safe_dir_abs = os.path.realpath(SAFE_DIRECTORY)
        
        # Construct the full path and get its absolute real path
        requested_path = os.path.join(safe_dir_abs, filename)
        requested_path_abs = os.path.realpath(requested_path)

        # Security Check: Ensure the resolved path is still within the safe directory.
        if not requested_path_abs.startswith(safe_dir_abs + os.sep):
             return "Error: Directory traversal attempt detected."
        
        if os.path.commonpath([safe_dir_abs]) != os.path.commonpath([safe_dir_abs, requested_path_abs]):
            return "Error: Directory traversal attempt detected."

        if os.path.isfile(requested_path_abs):
            with open(requested_path_abs, 'r') as f:
                return f.read()
        else:
            return "Error: File is not readable or does not exist."

    except Exception as e:
        return f"Error: Could not read the file. {e}"

def main():
    # Setup test environment
    if not os.path.exists(SAFE_DIRECTORY):
        os.makedirs(SAFE_DIRECTORY)
    with open(os.path.join(SAFE_DIRECTORY, "test1.txt"), "w") as f:
        f.write("This is a safe file.")
    with open(os.path.join(SAFE_DIRECTORY, "test2.log"), "w") as f:
        f.write("Another safe log file.")
    with open("unsafe.txt", "w") as f:
        f.write("This is an unsafe file.")
        
    print("--- Python Test Cases ---")
    
    # Test Case 1: Valid file
    print("1. Reading 'test1.txt':")
    print(read_file("test1.txt"))
    print()

    # Test Case 2: Another valid file
    print("2. Reading 'test2.log':")
    print(read_file("test2.log"))
    print()

    # Test Case 3: Non-existent file
    print("3. Reading 'nonexistent.txt':")
    print(read_file("nonexistent.txt"))
    print()

    # Test Case 4: Path traversal attempt
    print("4. Reading '../unsafe.txt':")
    print(read_file("../unsafe.txt"))
    print()
    
    # Test Case 5: Absolute path attempt
    print("5. Reading '/etc/passwd':")
    print(read_file("/etc/passwd"))
    print()

if __name__ == "__main__":
    main()