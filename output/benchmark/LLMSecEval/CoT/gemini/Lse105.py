import os
import stat
import sys

def create_secret_file(filename, content):
    """
    Creates a file with given content and restrictive permissions (owner read/write).
    This function uses POSIX-specific calls for security but includes a
    fallback for Windows.

    Args:
        filename (str): The name of the file to create.
        content (str): The string content to write to the file.

    Returns:
        bool: True for success, False for failure.
    """
    try:
        # For non-Windows (POSIX) systems, use a secure, atomic approach
        if sys.platform != "win32":
            # Define restrictive permissions: owner read/write (0o600)
            permissions = stat.S_IRUSR | stat.S_IWUSR

            # Flags for os.open: Write-only, create if not exists, truncate if exists
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            
            # Use os.open to create the file with permissions set atomically.
            # This avoids a TOCTOU (Time-of-check to time-of-use) race condition.
            # The 'with' statement ensures the file descriptor is closed automatically.
            with os.fdopen(os.open(filename, flags, permissions), 'w') as f:
                f.write(content)
            print(f"Successfully created and secured '{filename}' with permissions {oct(permissions)}.")
        else:
            # Fallback for Windows - less secure as permissions are set after creation.
            with open(filename, "w") as f:
                f.write(content)
            # os.chmod on Windows is limited. For better security, pywin32 would be needed.
            # This sets the file to be readable and writable by the owner.
            os.chmod(filename, stat.S_IWRITE | stat.S_IREAD)
            print(f"Successfully created '{filename}' on Windows with basic permissions.")
            
        return True
    except OSError as e:
        print(f"Error creating file '{filename}': {e}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        return False

def main():
    """ Main function with 5 test cases """
    filename = "secret.txt"
    content = "U2FsdGVkX1/R+WzJcxgvX/Iw=="

    for i in range(1, 6):
        print(f"--- Test Case {i} ---")
        # Clean up before each test to ensure a fresh start
        if os.path.exists(filename):
            try:
                os.remove(filename)
            except OSError as e:
                print(f"Cleanup failed before test: {e}", file=sys.stderr)
        
        success = create_secret_file(filename, content)
        print(f"Test {i} result: {'Success' if success else 'Failure'}\n")

if __name__ == "__main__":
    main()