import os
import stat
import sys

CONTENT = "U2FsdGVkX1/R+WzJcxgvX/Iw=="

def manage_secret_file(filename):
    """
    Creates a file, writes content, sets restrictive permissions, and prints them.
    This function uses low-level I/O to create the file with the correct
    permissions atomically, which is more secure than creating and then changing permissions.
    """
    print(f"Processing file: {filename}")
    fd = -1  # File descriptor
    try:
        # Define restrictive permissions based on OS
        # For POSIX systems, 0o600 is rw-------.
        # For Windows, stat.S_IREAD | stat.S_IWRITE is owner read/write.
        permissions = 0o600 if sys.platform != "win32" else (stat.S_IREAD | stat.S_IWRITE)

        # Atomically create the file with specified permissions.
        # os.O_TRUNC will clear the file if it already exists.
        fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, permissions)
        
        # Write the content as bytes
        os.write(fd, CONTENT.encode('utf-8'))
        print("File created and content written.")

        # Get and print permissions
        file_stat = os.stat(filename)
        current_permissions = stat.S_IMODE(file_stat.st_mode)
        
        if sys.platform != "win32":
            print(f"Current file permissions: {oct(current_permissions)}")
        else:
            # On Windows, octal representation is less meaningful.
            perms_str = []
            if current_permissions & stat.S_IREAD:
                perms_str.append("Read")
            if current_permissions & stat.S_IWRITE:
                perms_str.append("Write")
            print(f"Current file permissions (owner): {'/'.join(perms_str)}")

    except OSError as e:
        print(f"Error processing file {filename}: {e}", file=sys.stderr)
    finally:
        if fd != -1:
            try:
                os.close(fd)
            except OSError as e:
                print(f"Error closing file descriptor for {filename}: {e}", file=sys.stderr)
        print("---")


def cleanup(filename):
    """Deletes the specified file if it exists."""
    try:
        if os.path.exists(filename):
            os.remove(filename)
    except OSError as e:
        print(f"Error cleaning up file {filename}: {e}", file=sys.stderr)


def main():
    """Main function to run test cases."""
    for i in range(1, 6):
        test_filename = f"secret_python_{i}.txt"
        try:
            manage_secret_file(test_filename)
        finally:
            cleanup(test_filename)

if __name__ == "__main__":
    main()