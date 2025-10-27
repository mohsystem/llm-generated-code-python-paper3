import os
import stat
import sys

def create_config_file(filename):
    """
    Creates a file with owner read/write permissions (0o600).
    This function is idempotent: it returns True if the file is successfully
    created or if it already exists.
    
    Args:
        filename (str): The name of the file to create.

    Returns:
        bool: True on success (created or exists), False on error.
    """
    try:
        # Define permissions: Read and write for the owner.
        # stat.S_IRUSR | stat.S_IWUSR is equivalent to octal 0o600.
        permissions = stat.S_IRUSR | stat.S_IWUSR
        
        # Use os.O_EXCL to ensure the call fails if the file already exists.
        # This makes the check and creation an atomic operation.
        fd = os.open(filename, os.O_CREAT | os.O_WRONLY | os.O_EXCL, permissions)
        os.close(fd)
        print(f"Successfully created '{filename}' with owner read/write permissions.")
        return True
    except FileExistsError:
        print(f"File '{filename}' already exists.")
        return True
    except OSError as e:
        print(f"Error creating file '{filename}': {e}", file=sys.stderr)
        return False

def main():
    """Runs test cases for the create_config_file function."""
    filename = "important_config"
    other_filename = "another_config.txt"

    print("--- Test Case 1: Create file for the first time ---")
    create_config_file(filename)

    print("\n--- Test Case 2: Try to create the same file again ---")
    create_config_file(filename)

    print("\n--- Test Case 3: Delete the file ---")
    if os.path.exists(filename):
        try:
            os.remove(filename)
            print(f"Deleted '{filename}' for re-testing.")
        except OSError as e:
            print(f"Error deleting file '{filename}': {e}", file=sys.stderr)

    print("\n--- Test Case 4: Create the file again after deletion ---")
    create_config_file(filename)

    print("\n--- Test Case 5: Create a different file ---")
    create_config_file(other_filename)

    # Cleanup
    print("\n--- Cleanup ---")
    for f in [filename, other_filename]:
        if os.path.exists(f):
            try:
                os.remove(f)
            except OSError as e:
                print(f"Error during cleanup of '{f}': {e}", file=sys.stderr)
    print("Cleanup complete.")

if __name__ == "__main__":
    main()