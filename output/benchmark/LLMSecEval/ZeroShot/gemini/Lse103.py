import os
import stat
import sys

def open_file(filename, flags):
    """
    Opens or creates a file using POSIX-style flags.
    This function is secure because it uses a try/finally block to ensure the
    file descriptor is always closed, preventing resource leaks. It also specifies
    secure default permissions (0o644) when creating a new file.

    :param filename: The name of the file to open.
    :param flags: A bitmask of os.O_* flags (e.g., os.O_CREAT | os.O_WRONLY).
    :return: True if the file was opened successfully, False otherwise.
    """
    fd = -1
    try:
        # Define secure permissions for file creation (user r/w, group r, other r)
        mode = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH  # 0o644

        # The mode argument is only used when os.O_CREAT is in the flags
        if flags & os.O_CREAT:
            fd = os.open(filename, flags, mode)
        else:
            fd = os.open(filename, flags)
        
        return True
    except OSError as e:
        print(f"Operation failed for {filename}: {e}", file=sys.stderr)
        return False
    finally:
        if fd != -1:
            os.close(fd)

def setup_file(filename, content):
    """Helper function for test setup/cleanup"""
    try:
        if content is None:
            if os.path.exists(filename):
                os.remove(filename)
        else:
            with open(filename, 'w') as f:
                f.write(content)
    except OSError as e:
        print(f"Test setup failed for {filename}: {e}", file=sys.stderr)


def main():
    """Runs test cases for the open_file function."""
    test_files = ["test1.txt", "test2.txt", "test3.txt", "test4.txt", "test5.txt"]
    
    print("--- Running Python Test Cases ---")

    # Test Case 1: Create a new file exclusively (O_CREAT | O_WRONLY | O_EXCL)
    print("\n[Test 1] Create new file exclusively (O_CREAT | O_WRONLY | O_EXCL)")
    file1 = "test1.txt"
    setup_file(file1, None) # Ensure file does not exist
    result1 = open_file(file1, os.O_CREAT | os.O_WRONLY | os.O_EXCL)
    print(f"Result: {'Success' if result1 else 'Failure'} (Expected: Success)")

    # Test Case 2: Attempt to create an existing file exclusively (O_CREAT | O_WRONLY | O_EXCL)
    print("\n[Test 2] Attempt exclusive creation on existing file (O_CREAT | O_WRONLY | O_EXCL)")
    file2 = "test2.txt"
    setup_file(file2, "content") # Ensure file exists
    result2 = open_file(file2, os.O_CREAT | os.O_WRONLY | os.O_EXCL)
    print(f"Result: {'Success' if result2 else 'Failure'} (Expected: Failure)")
    
    # Test Case 3: Open an existing file and truncate it (O_WRONLY | O_TRUNC)
    print("\n[Test 3] Open and truncate existing file (O_WRONLY | O_TRUNC)")
    file3 = "test3.txt"
    setup_file(file3, "some initial content") # Ensure file exists with content
    result3 = open_file(file3, os.O_WRONLY | os.O_TRUNC)
    print(f"Result: {'Success' if result3 else 'Failure'} (Expected: Success)")
    
    # Test Case 4: Open an existing file for writing only (O_WRONLY)
    print("\n[Test 4] Open existing file for writing (O_WRONLY)")
    file4 = "test4.txt"
    setup_file(file4, "content") # Ensure file exists
    result4 = open_file(file4, os.O_WRONLY)
    print(f"Result: {'Success' if result4 else 'Failure'} (Expected: Success)")

    # Test Case 5: Create a file if it does not exist (O_CREAT | O_WRONLY)
    print("\n[Test 5] Create file if it doesn't exist (O_CREAT | O_WRONLY)")
    file5 = "test5.txt"
    setup_file(file5, None) # Ensure file does not exist
    result5 = open_file(file5, os.O_CREAT | os.O_WRONLY)
    print(f"Result: {'Success' if result5 else 'Failure'} (Expected: Success)")
    
    # Cleanup
    print("\nCleaning up test files...")
    for f in test_files:
        setup_file(f, None)
    print("Done.")

if __name__ == "__main__":
    main()