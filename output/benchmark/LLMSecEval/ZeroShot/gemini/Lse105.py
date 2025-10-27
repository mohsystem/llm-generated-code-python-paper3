import os
import stat
import sys

def create_and_secure_file(filename, content):
    """
    Creates a file, writes content, and sets restrictive permissions securely.

    This implementation uses low-level file operations to set permissions at
    creation time, which is more secure against TOCTOU (Time-of-Check, Time-of-Use)
    race conditions.

    Args:
        filename (str): The name of the file to create.
        content (str): The string content to write to the file.

    Returns:
        bool: True if successful, False otherwise.
    """
    try:
        # Define secure permissions: read/write for owner only (0o600).
        permissions = stat.S_IRUSR | stat.S_IWUSR

        # Use os.open to create the file with specified permissions atomically.
        # Flags: Write-only, create if not exists, truncate if exists.
        fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, permissions)

        # os.fdopen() converts the file descriptor to a file object.
        # The 'with' statement ensures the file is closed properly.
        with os.fdopen(fd, 'w') as f:
            f.write(content)

        print(f"Successfully created and secured file {filename}")
        return True
    except OSError as e:
        print(f"Error creating or securing file {filename}: {e}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"An unexpected error occurred with {filename}: {e}", file=sys.stderr)
        return False

def main():
    """Main function to run test cases."""
    content = "U2FsdGVkX1/R+WzJcxgvX/Iw=="
    
    # 5 Test Cases: Create 5 separate files to demonstrate the function.
    for i in range(1, 6):
        filename = f"secret{i}.txt"
        print(f"\n--- Test Case {i}: Creating {filename} ---")
        success = create_and_secure_file(filename, content)
        if success:
            print(f"Test Case {i} PASSED.")
        else:
            print(f"Test Case {i} FAILED.")

if __name__ == "__main__":
    main()