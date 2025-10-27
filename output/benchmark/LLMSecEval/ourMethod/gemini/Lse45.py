import os
import stat
import sys

# Define a maximum file size to prevent large file attacks
MAX_FILE_SIZE = 1024 * 1024  # 1 MB

def read_file_from_safe_directory(safe_dir, filename):
    """
    Reads a file from a safe directory using file descriptors to prevent TOCTOU
    and path traversal vulnerabilities.

    Args:
        safe_dir (str): The path to the trusted directory.
        filename (str): The name of the file to read.

    Returns:
        bytes: The content of the file, or None on failure.
    """
    # 1. Validate filename to ensure it is a simple name, not a path.
    if os.path.sep in filename or (os.path.altsep and os.path.altsep in filename):
        print("Error: Filename must not contain path separators.", file=sys.stderr)
        return None
    if filename == ".." or filename == ".":
        print("Error: Invalid filename.", file=sys.stderr)
        return None

    dir_fd = -1
    try:
        # 2. Get a file descriptor for the safe directory.
        dir_fd = os.open(safe_dir, os.O_RDONLY | os.O_DIRECTORY)

        # 3. Open the file relative to the directory descriptor.
        #    O_NOFOLLOW prevents following symbolic links.
        #    This is the "open" step in "open-then-validate".
        #    Using a 'with' statement ensures the file descriptor is closed.
        with os.open(filename, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dir_fd) as fd:
            # 4. Validate the opened file handle using fstat.
            st = os.fstat(fd)

            # Ensure it's a regular file.
            if not stat.S_ISREG(st.st_mode):
                print(f"Error: '{filename}' is not a regular file.", file=sys.stderr)
                return None

            # Ensure file size is within limits.
            if st.st_size > MAX_FILE_SIZE:
                print(f"Error: File '{filename}' exceeds size limit.", file=sys.stderr)
                return None

            # 5. Read from the validated file descriptor.
            return os.read(fd, st.st_size)

    except FileNotFoundError:
        print(f"Error: File '{filename}' not found in '{safe_dir}'.", file=sys.stderr)
        return None
    except OSError as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        return None
    finally:
        if dir_fd != -1:
            os.close(dir_fd)


def main():
    """Main function with test cases."""
    safe_dir_name = "python_safe_dir"
    secret_file_name = "python_secret_file.txt"

    # Setup test environment
    try:
        os.makedirs(safe_dir_name, exist_ok=True)
        with open(os.path.join(safe_dir_name, "good.txt"), "w") as f:
            f.write("This is a safe file.")
        with open(secret_file_name, "w") as f:
            f.write("This is a secret.")
        
        # Create a large file
        with open(os.path.join(safe_dir_name, "large.txt"), "wb") as f:
            f.write(b'\0' * (MAX_FILE_SIZE + 1))

        # Create a symbolic link
        symlink_path = os.path.join(safe_dir_name, "symlink.txt")
        if os.path.lexists(symlink_path):
             os.remove(symlink_path)
        # Use absolute path for symlink target for reliability
        os.symlink(os.path.abspath(secret_file_name), symlink_path)
        
        print("--- Running Test Cases ---")

        # Test Case 1: Read a valid file
        print("\n1. Reading a valid file (good.txt):")
        content = read_file_from_safe_directory(safe_dir_name, "good.txt")
        if content:
            print(f"   Success. Content: {content.decode()}")
        else:
            print("   Failed.")

        # Test Case 2: Read a non-existent file
        print("\n2. Reading a non-existent file (nonexistent.txt):")
        content = read_file_from_safe_directory(safe_dir_name, "nonexistent.txt")
        if not content:
            print("   Success: Read operation failed as expected.")
        else:
            print("   Failed: Code read a non-existent file.")
        
        # Test Case 3: Read a file that is too large
        print("\n3. Reading a large file (large.txt):")
        content = read_file_from_safe_directory(safe_dir_name, "large.txt")
        if not content:
            print("   Success: Read operation failed as expected.")
        else:
            print("   Failed: Code read an oversized file.")

        # Test Case 4: Attempt path traversal
        print(f"\n4. Attempting path traversal (../{secret_file_name}):")
        content = read_file_from_safe_directory(safe_dir_name, f"../{secret_file_name}")
        if not content:
            print("   Success: Path traversal was blocked.")
        else:
            print("   Failed: Path traversal was successful.")

        # Test Case 5: Attempt to read a symbolic link
        print("\n5. Reading a symbolic link (symlink.txt):")
        content = read_file_from_safe_directory(safe_dir_name, "symlink.txt")
        if not content:
            print("   Success: Reading symbolic link was blocked.")
        else:
            print("   Failed: Code followed a symbolic link.")

    except Exception as e:
        print(f"An error occurred during test setup or execution: {e}", file=sys.stderr)
    finally:
        # Cleanup
        for f in ["good.txt", "large.txt", "symlink.txt"]:
            path = os.path.join(safe_dir_name, f)
            if os.path.lexists(path):
                os.remove(path)
        if os.path.exists(safe_dir_name):
            os.rmdir(safe_dir_name)
        if os.path.exists(secret_file_name):
            os.remove(secret_file_name)


if __name__ == "__main__":
    main()