import subprocess
import os

def display_file_content(filename):
    """
    Securely displays a file's content using a system command.
    Note: On Windows, the command "cat" might need to be changed to "type".
    """
    print(f"--- Attempting to display: '{filename}' ---")

    # Using a list of arguments with subprocess.run (with shell=False, the default)
    # is secure. The filename is passed as a single argument and is not interpreted
    # by a shell, thus preventing command injection.
    try:
        # We use check=False to handle non-zero exit codes in our own code.
        command = ["cat", filename]
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        
        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            # Using print() for stderr to ensure it's distinct in output
            print(result.stderr, end="")
            
        print(f"\n-> Command finished with exit code: {result.returncode}")

    except FileNotFoundError:
        print(f"Error: The command 'cat' was not found on this system.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    
    print("--- End of attempt ---\n")

def main():
    """
    Main function to set up, run test cases, and clean up.
    """
    # 1. Setup: Create dummy files for testing
    file1 = "test_file_1.txt"
    file2 = "file with spaces.txt"
    try:
        with open(file1, "w", encoding="utf-8") as f:
            f.write("Hello from test file 1.")
        with open(file2, "w", encoding="utf-8") as f:
            f.write("This file has spaces in its name.")
        print("Created test files.\n")
    except IOError as e:
        print(f"Failed to create test files: {e}")
        return

    # 2. Test cases
    test_cases = [
        file1,                                # 1. Valid file
        file2,                                # 2. Valid file with spaces
        "non_existent_file.txt",              # 3. Non-existent file
        "test_file_1.txt; ls -l",             # 4. Command injection attempt (benign)
        "| whoami"                            # 5. Command injection attempt (malicious)
    ]

    for test_case in test_cases:
        display_file_content(test_case)

    # 3. Cleanup: Delete the dummy files
    try:
        os.remove(file1)
        os.remove(file2)
        print("Cleaned up test files.")
    except IOError as e:
        print(f"Failed to clean up test files: {e}")

if __name__ == "__main__":
    main()