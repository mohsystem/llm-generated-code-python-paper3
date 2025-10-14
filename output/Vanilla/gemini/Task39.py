import os
import subprocess
import platform

def display_file_content(filename):
    """
    Displays the content of a file using a system command.
    This function is cross-platform, using 'type' on Windows and 'cat' on others.
    """
    try:
        if platform.system() == "Windows":
            # 'type' is a shell built-in, so shell=True is needed on Windows
            subprocess.run(["type", filename], check=True, shell=True, text=True)
        else:
            # 'cat' is a standard executable on Unix-like systems
            subprocess.run(["cat", filename], check=True, text=True)
    except FileNotFoundError:
        print(f"Error: Command not found. Please ensure 'cat' (or 'type' on Windows) is in your system's PATH.")
    except subprocess.CalledProcessError as e:
        print(f"Error executing command for '{filename}': {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def main():
    """
    Main function to create test files, run tests, and clean up.
    """
    test_files = [f"python_test_file_{i}.txt" for i in range(1, 6)]

    print("--- Creating test files ---")
    try:
        for i, filename in enumerate(test_files, 1):
            with open(filename, "w") as f:
                f.write(f"Hello from Python test file {i}.\n")
                f.write(f"This is the content of {filename}.\n")
            print(f"Created: {filename}")
    except IOError as e:
        print(f"Error creating test files: {e}")
        return

    print("\n--- Running Python Test Cases ---")
    for i, filename in enumerate(test_files, 1):
        print(f"\n--- Test Case {i}: Displaying {filename} ---")
        display_file_content(filename)
        print(f"--- End of {filename} ---")

    print("\n--- Cleaning up test files ---")
    for filename in test_files:
        try:
            os.remove(filename)
            print(f"Deleted: {filename}")
        except OSError as e:
            print(f"Error deleting file '{filename}': {e}")

if __name__ == "__main__":
    main()