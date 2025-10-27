import os
import stat

def create_and_secure_file(filename, content):
    """
    Creates a file, writes content to it, and sets restrictive permissions.
    Permissions are set to 600 (owner-read/write). Note: On Windows,
    os.chmod() has limited effect and primarily toggles the read-only flag.
    """
    try:
        # 1. Write the string to the file, overwriting if it exists.
        with open(filename, 'w') as f:
            f.write(content)
        print(f"Successfully created and wrote to {filename}")

        # 2. Change permissions to 600 (owner read/write).
        permissions = stat.S_IRUSR | stat.S_IWUSR
        os.chmod(filename, permissions)
        print(f"Set permissions for {filename} to restrictive (owner-read/write).")

    except (IOError, OSError) as e:
        print(f"An error occurred with file '{filename}': {e}")

def main():
    """Main function to run test cases."""
    content = "U2FsdGVkX1/R+WzJcxgvX/Iw=="
    
    # 5 test cases, creating 5 different files.
    for i in range(1, 6):
        filename = f"secret{i}.txt"
        print(f"\n--- Test Case {i}: Creating {filename} ---")
        create_and_secure_file(filename, content)

if __name__ == "__main__":
    main()