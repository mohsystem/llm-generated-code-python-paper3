import os
import stat
import sys

def manage_secret_file(filename, content):
    """
    Creates a file, writes content, sets restrictive permissions, and prints them.
    """
    print(f"Processing file: {filename}")
    try:
        # 1. Create a file and write the string to it.
        with open(filename, 'w') as f:
            f.write(content)
        print(f"  - Successfully wrote to {filename}")

        # 2. Change the permissions to restrictive (owner read/write: 600).
        # This is primarily for POSIX systems (Linux, macOS).
        # On Windows, chmod has limited effect.
        # 0o600 is an octal literal for permissions rw-------
        os.chmod(filename, 0o600)
        print("  - Set permissions to 0o600 (rw-------)")

        # 3. Print the permissions of the file.
        # Get the status of the file
        file_stat = os.stat(filename)
        # Extract and print permission bits in octal
        permissions = stat.S_IMODE(file_stat.st_mode)
        print(f"  - Current permissions: {oct(permissions)}")

    except (IOError, OSError) as e:
        print(f"An error occurred: {e}", file=sys.stderr)
    finally:
        # Clean up the created file for the next test case
        if os.path.exists(filename):
            os.remove(filename)
            print(f"  - Cleaned up file: {filename}")
        print("--------------------")


if __name__ == "__main__":
    SECRET_STRING = "U2FsdGVkX1/R+WzJcxgvX/Iw=="
    
    # Test Case 1
    manage_secret_file("secret.txt", SECRET_STRING)

    # Test Case 2
    manage_secret_file("secret_file_2.txt", SECRET_STRING)
    
    # Test Case 3
    manage_secret_file("another_secret.log", SECRET_STRING)
    
    # Test Case 4
    manage_secret_file("temp_secret_4.dat", SECRET_STRING)
    
    # Test Case 5
    manage_secret_file("last_secret.txt", SECRET_STRING)