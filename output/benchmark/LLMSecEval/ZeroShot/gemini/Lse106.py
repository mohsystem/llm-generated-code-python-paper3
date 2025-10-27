import os
import stat
import tempfile

def create_secret_file(secret_info: str) -> str or None:
    """
    Creates a secure temporary file, writes secret info to it, sets its
    permissions to owner-read-only (0400), and returns the filename.

    Args:
        secret_info: The string content to write to the file.

    Returns:
        The absolute path of the created file, or None on failure.
    """
    file_path = None
    try:
        # 1. Create a secure temporary file. mkstemp is used to avoid race conditions.
        # It returns a low-level file descriptor and the file path.
        fd, file_path = tempfile.mkstemp(prefix="secret_", suffix=".txt")

        # 2. Write the super secret info to it using the file descriptor.
        with os.fdopen(fd, 'w') as temp_file:
            temp_file.write(secret_info)

        # 3. Change the permissions to read-only for the owner (0o400).
        # stat.S_IRUSR is a constant for owner read permission.
        os.chmod(file_path, stat.S_IRUSR)

        # 4. Return the name of the file.
        return file_path
    except Exception as e:
        print(f"An error occurred: {e}")
        # Clean up the file if it exists after an error.
        if file_path and os.path.exists(file_path):
            os.remove(file_path)
        return None

def main():
    """Main function to run test cases."""
    print("Running Python Test Cases:")
    created_files = []
    for i in range(1, 6):
        secret = f"Python super secret key #{i} is PYK{(i * 456)}"
        file_name = create_secret_file(secret)
        if file_name:
            print(f"Test Case {i}: Secret file created at: {file_name}")
            created_files.append(file_name)
        else:
            print(f"Test Case {i}: Failed to create secret file.")
    
    # Optional: Clean up created files at the end of the script
    # for f in created_files:
    #     try:
    #         os.remove(f)
    #     except OSError:
    #         pass


if __name__ == "__main__":
    main()