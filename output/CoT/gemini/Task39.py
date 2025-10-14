import subprocess
import platform
import os
import re

def display_file_contents(filename: str):
    """
    Displays the contents of a file using a system command.
    This implementation uses the subprocess module with a list of arguments
    to prevent command injection vulnerabilities.

    Args:
        filename: The name of the file to display.
    """
    print(f"--- Attempting to display file: {filename} ---")
    
    # Security Check 1: Validate filename format to prevent path traversal and shell metacharacters.
    # This regex ensures the filename is simple and does not contain dangerous characters.
    if not re.match(r'^[a-zA-Z0-9._-]+$', filename) or '..' in filename:
        print("Error: Invalid or unsafe filename provided.")
        print("--------------------------------------------------\n")
        return

    # Security Check 2: Verify that the file exists and is a file.
    if not os.path.isfile(filename):
        print("Error: File does not exist or is not a regular file.")
        print("--------------------------------------------------\n")
        return
        
    try:
        command = ["type"] if platform.system() == "Windows" else ["cat"]
        
        # Security Core: Pass the command and its arguments as a list.
        # This ensures the filename is treated as a single argument and is not
        # interpreted by the shell, thus preventing command injection.
        command.append(filename)

        result = subprocess.run(command, check=True, text=True, capture_output=True)
        
        print(result.stdout.strip())
        print(f"\n> Command finished with exit code: {result.returncode}")

    except FileNotFoundError:
        # This error occurs if the command (e.g., 'cat') is not found in the system's PATH.
        print(f"Error: Command '{command[0]}' not found.")
    except subprocess.CalledProcessError as e:
        # This error is raised by check=True if the command returns a non-zero exit code
        # (e.g., if the file does not exist, though we already checked for that).
        print(f"Error executing command. Exit code: {e.returncode}")
        print(f"Stderr: {e.stderr.strip()}")
    
    print("--------------------------------------------------\n")


if __name__ == "__main__":
    # Setup: Create some test files
    try:
        with open("test1.txt", "w") as f:
            f.write("This is a safe test file.")
        with open("safe-file.log", "w") as f:
            f.write("This is another safe log file.")
    except IOError as e:
        print(f"Failed to create test files: {e}")
        exit()

    # Test Case 1: A valid and safe filename
    display_file_contents("test1.txt")
    
    # Test Case 2: Another valid filename with a hyphen
    display_file_contents("safe-file.log")

    # Test Case 3: A file that does not exist
    display_file_contents("nonexistent.txt")

    # Test Case 4: A malicious input attempting command injection
    # This will be caught by the validation regex.
    display_file_contents("test1.txt; ls")

    # Test Case 5: A malicious input attempting path traversal
    # This will be caught by the validation check.
    display_file_contents("../some_other_file")

    # Cleanup: Delete the test files
    os.remove("test1.txt")
    os.remove("safe-file.log")