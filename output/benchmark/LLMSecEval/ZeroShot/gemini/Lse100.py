import os
import stat
import sys

def create_secure_file(file_path: str) -> bool:
    """
    Atomically creates a file with secure permissions 0600 (read/write for owner only).
    
    Args:
        file_path: The path to the file to be created.
    
    Returns:
        True on success, False on failure.
    """
    if not file_path or not isinstance(file_path, str):
        print("Error: File path must be a non-empty string.", file=sys.stderr)
        return False
        
    # Security: Basic path traversal check
    if ".." in os.path.normpath(file_path).split(os.path.sep):
        print(f"Error: Invalid file path (contains '..'): {file_path}", file=sys.stderr)
        return False

    # Check if parent directory exists
    parent_dir = os.path.dirname(file_path)
    if parent_dir and not os.path.isdir(parent_dir):
        print(f"Error: Parent directory does not exist for path: {file_path}", file=sys.stderr)
        return False

    # Permissions: read/write for owner only (0o600)
    permissions = stat.S_IRUSR | stat.S_IWUSR

    # Flags: Write-only, create if not exists, and exclusive (fail if it exists).
    # This combination ensures an atomic check-and-create operation.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    
    fd = -1
    try:
        # The 'mode' argument to os.open() is used to set file permissions on creation.
        # It is affected by the process's umask.
        fd = os.open(file_path, flags, permissions)
        print(f"Successfully created secure file: {file_path}")
        return True
    except FileExistsError:
        print(f"Error: File already exists: {file_path}", file=sys.stderr)
        return False
    except OSError as e:
        print(f"Error creating file '{file_path}': {e}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        return False
    finally:
        if fd != -1:
            os.close(fd)

def main():
    """Runs test cases for the create_secure_file function."""
    print("--- Python Test Cases ---")
    
    # Test Case 1: Standard successful creation
    print("\nTest Case 1: Create 'important_config.py'")
    create_secure_file("important_config.py")

    # Test Case 2: Attempt to create a file that already exists
    print("\nTest Case 2: Attempt to create existing file 'important_config.py'")
    create_secure_file("important_config.py")

    # Test Case 3: Create a file with a relative path
    print("\nTest Case 3: Create './another_config.py.cfg'")
    create_secure_file("./another_config.py.cfg")

    # Test Case 4: Attempt to create a file in a non-existent directory
    print("\nTest Case 4: Attempt to create in a non-existent directory")
    create_secure_file("non_existent_dir/some_file.txt")

    # Test Case 5: Another successful creation
    print("\nTest Case 5: Create 'config_3.py.dat'")
    create_secure_file("config_3.py.dat")

if __name__ == "__main__":
    main()