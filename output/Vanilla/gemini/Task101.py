import os
import stat

def create_and_make_executable(filename):
    """
    Creates a file with the given name, writes a simple shell script to it,
    and makes it executable.

    :param filename: The name of the file to create.
    :return: True if successful, False otherwise.
    """
    try:
        # Create the file and write content
        with open(filename, 'w') as f:
            f.write("#!/bin/bash\n")
            f.write(f"echo \"Hello from '{filename}'!\"\n")
        print(f"File created: {filename}")

        # Make the file executable (add execute permissions for owner, group, and others)
        # This is equivalent to `chmod +x` or `chmod 755` on existing permissions.
        current_permissions = os.stat(filename).st_mode
        os.chmod(filename, current_permissions | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        
        print(f"File permissions set to executable.")
        return True
    except (IOError, OSError) as e:
        print(f"An error occurred: {e}")
        return False

if __name__ == "__main__":
    # 5 Test Cases
    test_files = ["script.sh", "test_script_1.sh", "test_script_2.sh", "another.sh", "final.sh"]
    for i, filename in enumerate(test_files):
        print(f"--- Test Case {i + 1}: {filename} ---")
        success = create_and_make_executable(filename)
        print(f"Result: {'SUCCESS' if success else 'FAILURE'}")
        print()