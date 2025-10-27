import os
import sys

# Note: This code uses POSIX-specific functions and flags from the 'os' module.
# It will work on Linux, macOS, and other UNIX-like systems.
# Full functionality, especially of all flags, may not be available on Windows.

def open_file_with_flags(pathname, flags):
    """
    Opens a file using low-level POSIX flags.
    This function mimics the behavior of C's open() call.
    """
    # File permissions for creation (0o644 is rw-r--r--)
    mode = 0o644

    # Build a string of flag names for readable output
    flag_names = []
    if flags & os.O_CREAT: flag_names.append("O_CREAT")
    if flags & os.O_WRONLY: flag_names.append("O_WRONLY")
    if flags & os.O_TRUNC: flag_names.append("O_TRUNC")
    if flags & os.O_EXCL: flag_names.append("O_EXCL")
    print(f"Attempting to open '{pathname}' with flags: {' | '.join(flag_names)}")

    try:
        # os.open returns a low-level file descriptor (an integer)
        fd = os.open(pathname, flags, mode)
        print(f"  -> Success: File opened/created with fd = {fd}")
        # Write some data to the file
        os.write(fd, b"hello")
        os.close(fd)
        return True
    except OSError as e:
        print(f"  -> Error: {e.strerror} (errno {e.errno})")
        return False

def main():
    """Main function with test cases."""
    filename = "python_test_file.txt"

    # Ensure the file does not exist before starting
    if os.path.exists(filename):
        os.remove(filename)

    print("--- Python File Open Flags Demonstration (using os.open) ---")

    # These flags need to exist in the os module. If not, we can't run.
    required_flags = ['O_CREAT', 'O_WRONLY', 'O_EXCL', 'O_TRUNC']
    if not all(hasattr(os, flag) for flag in required_flags):
        print(f"This script requires POSIX file flags which are not available on {sys.platform}.")
        return
        
    # Test 1: O_CREAT | O_WRONLY | O_EXCL on a new file
    print("\n[Test 1: Exclusive Create on new file - Should Succeed]")
    open_file_with_flags(filename, os.O_CREAT | os.O_WRONLY | os.O_EXCL)

    # Test 2: O_CREAT | O_WRONLY | O_EXCL on an existing file
    print("\n[Test 2: Exclusive Create on existing file - Should Fail]")
    open_file_with_flags(filename, os.O_CREAT | os.O_WRONLY | os.O_EXCL)

    # Test 3: O_CREAT | O_WRONLY on an existing file
    print("\n[Test 3: Open for Writing (O_WRONLY) - Should Succeed]")
    open_file_with_flags(filename, os.O_CREAT | os.O_WRONLY)

    # Test 4: O_CREAT | O_WRONLY | O_TRUNC on an existing file
    print("\n[Test 4: Open for Writing with Truncate (O_TRUNC) - Should Succeed]")
    open_file_with_flags(filename, os.O_CREAT | os.O_WRONLY | os.O_TRUNC)

    # Test 5: Cleanup
    print("\n[Test 5: Cleanup]")
    try:
        os.remove(filename)
        print(f"  -> Success: Deleted '{filename}'")
    except OSError as e:
        print(f"  -> Error: Failed to delete '{filename}': {e.strerror}")

if __name__ == "__main__":
    main()