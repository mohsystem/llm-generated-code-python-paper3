import os
import stat
import sys

def create_secure_file(file_path):
    """
    Atomically creates a file with secure permissions 600 (owner read/write).
    This function is primarily designed for POSIX-compliant systems.
    
    Args:
        file_path (str): The path of the file to create.
    
    Returns:
        bool: True if the file was created successfully, False otherwise.
    """
    # Permissions: rw------- (owner read/write).
    # S_IRUSR is read for user, S_IWUSR is write for user.
    permissions = stat.S_IRUSR | stat.S_IWUSR

    # Flags for atomic creation:
    # O_WRONLY: Open for writing only.
    # O_CREAT: Create the file if it does not exist.
    # O_EXCL: Fail if the file already exists. This prevents race conditions.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL

    try:
        # os.open is a low-level function that allows setting mode on creation,
        # making the operation atomic and secure.
        fd = os.open(file_path, flags, permissions)
        # The file is now created. We can close the descriptor immediately.
        os.close(fd)
        print(f"Successfully created secure file: {file_path}")
        return True
    except FileExistsError:
        print(f"Error: File already exists: {file_path}", file=sys.stderr)
        return False
    except OSError as e:
        # Catches other errors like permission denied for the parent directory.
        print(f"An OS error occurred: {e}", file=sys.stderr)
        return False

def main():
    file_name1 = "important_config"
    file_name2 = "another_config"
    invalid_path = "non_existent_dir/important_config"
    relative_path = "./temp_config"

    print("--- Test Case 1: Create new file ---")
    create_secure_file(file_name1)

    print("\n--- Test Case 2: Attempt to create existing file ---")
    create_secure_file(file_name1)

    print("\n--- Test Case 3: Create a different new file ---")
    create_secure_file(file_name2)

    print("\n--- Test Case 4: Attempt to create file in non-existent directory ---")
    create_secure_file(invalid_path)
    
    print("\n--- Test Case 5: Create a file with a relative path ---")
    create_secure_file(relative_path)

    # Cleanup
    print("\n--- Cleaning up created files ---")
    for f in [file_name1, file_name2, relative_path]:
        try:
            if os.path.exists(f):
                os.remove(f)
        except OSError as e:
            print(f"Error removing file {f}: {e}", file=sys.stderr)
    print("Cleanup complete.")

if __name__ == "__main__":
    main()