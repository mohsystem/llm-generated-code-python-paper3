import os

def demonstrate_file_open(filename, mode):
    """
    Opens or creates a file with a specified mode to demonstrate flags.
    'w': (Write) Equivalent to O_CREAT | O_WRONLY | O_TRUNC
    'x': (Exclusive Creation) Equivalent to O_CREAT | O_WRONLY | O_EXCL

    In a real-world application, sanitize the 'filename' parameter to
    prevent path traversal vulnerabilities.
    """
    try:
        # The 'with' statement ensures the file is closed automatically.
        with open(filename, mode) as f:
            print(f"Success: Opened/created '{filename}' with mode '{mode}'.")
            f.write("Python test content.\n")
            return True
    except FileExistsError:
        print(f"Error: File '{filename}' already exists (mode 'x' / O_EXCL effect).")
        return False
    except IOError as e:
        print(f"Error handling file '{filename}': {e}")
        return False

def main():
    print("--- Python Test Cases ---")
    
    file1 = "test_python_1.txt"
    file2 = "test_python_2.txt"

    # TC1: 'w' (O_CREAT | O_WRONLY | O_TRUNC) on a new file.
    print(f"\n[TC1] Creating new file with mode 'w'...")
    demonstrate_file_open(file1, 'w')

    # TC2: 'w' (O_CREAT | O_WRONLY | O_TRUNC) on an existing file.
    print(f"\n[TC2] Opening existing file with 'w' (should truncate)...")
    demonstrate_file_open(file1, 'w')
    
    # TC3: 'x' (O_CREAT | O_WRONLY | O_EXCL) on a new file.
    print(f"\n[TC3] Creating new file with mode 'x' (exclusive)...")
    demonstrate_file_open(file2, 'x')
    
    # TC4: 'x' (O_CREAT | O_WRONLY | O_EXCL) on an existing file (should fail).
    print(f"\n[TC4] Attempting to create existing file with 'x' (should fail)...")
    demonstrate_file_open(file2, 'x')
    
    # TC5: Demonstrating O_WRONLY on an existing file using os.open.
    # Python's built-in open() doesn't have a direct O_WRONLY without truncation.
    # We use os.open for a direct mapping to the POSIX call.
    print(f"\n[TC5] Opening existing file with O_WRONLY (no truncate)...")
    try:
        # os.O_WRONLY is a direct mapping.
        fd = os.open(file1, os.O_WRONLY)
        print(f"Success: Opened '{file1}' with O_WRONLY. fd={fd}")
        os.write(fd, b"Appended.\n")
        os.close(fd)
    except OSError as e:
        print(f"Error with os.open: {e}")

    # Cleanup
    print("\n--- Cleanup ---")
    for f in [file1, file2]:
        if os.path.exists(f):
            os.remove(f)
    print("Cleanup complete.")

if __name__ == "__main__":
    main()