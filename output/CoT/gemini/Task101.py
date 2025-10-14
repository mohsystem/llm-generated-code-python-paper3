import os
import stat
import sys

def create_and_make_executable(filename):
    """
    Creates a file with the given name and makes it executable (rwxr-xr-x).
    
    Args:
        filename (str): The name of the file to create.
        
    Returns:
        bool: True if successful, False otherwise.
    """
    try:
        # For test repeatability, remove the file if it exists.
        if os.path.exists(filename):
            os.remove(filename)

        # Step 1: Create an empty file.
        with open(filename, 'w') as f:
            pass
        
        # Step 2: Set the permissions to rwxr-xr-x (octal 755).
        # S_IRWXU: Read, write, and execute for owner.
        # S_IRGRP: Read for group.
        # S_IXGRP: Execute for group.
        # S_IROTH: Read for others.
        # S_IXOTH: Execute for others.
        permissions = stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH
        os.chmod(filename, permissions)
        
        print(f"Successfully created and set permissions for '{filename}'.")
        return True
    except (OSError, IOError) as e:
        # Use sys.stderr for error messages.
        print(f"Error: Could not create or set permissions for '{filename}'.\nReason: {e}", file=sys.stderr)
        return False

def main():
    """Main function with 5 test cases."""
    test_files = [
        "script1.sh",
        "script2.sh",
        "script3.sh",
        "script4.sh",
        "script5.sh"
    ]
    
    for filename in test_files:
        print(f"--- Testing: {filename} ---")
        create_and_make_executable(filename)
        print()

if __name__ == "__main__":
    main()