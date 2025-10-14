
import os
import stat
import sys

def create_executable_script(file_name):
    """\n    Creates a file and makes it executable\n    \n    Args:\n        file_name: Name of the file to create\n        \n    Returns:\n        bool: True if successful, False otherwise\n    """
    try:
        # Create the file with proper permissions from the start
        # Use os.open with secure flags
        fd = os.open(file_name, 
                     os.O_CREAT | os.O_WRONLY | os.O_TRUNC,
                     0o644)
        
        # Write basic shell script header
        with os.fdopen(fd, 'w') as f:
            f.write("#!/bin/bash\\n")
            f.write("# This is an executable script\\n")
        
        # Make it executable (owner, group, others can execute)
        # Use stat module for secure permission setting
        current_permissions = os.stat(file_name).st_mode
        os.chmod(file_name, 
                current_permissions | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        
        return True
        
    except OSError as e:
        print(f"Error creating executable script: {e}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return False


def main():
    """Main function with test cases"""
    
    print("Test Case 1: Create script.sh")
    result1 = create_executable_script("script.sh")
    print(f"Result: {'Success' if result1 else 'Failed'}\\n")
    
    print("Test Case 2: Create test_script.sh")
    result2 = create_executable_script("test_script.sh")
    print(f"Result: {'Success' if result2 else 'Failed'}\\n")
    
    print("Test Case 3: Create another_script.sh")
    result3 = create_executable_script("another_script.sh")
    print(f"Result: {'Success' if result3 else 'Failed'}\\n")
    
    print("Test Case 4: Create deploy.sh")
    result4 = create_executable_script("deploy.sh")
    print(f"Result: {'Success' if result4 else 'Failed'}\\n")
    
    print("Test Case 5: Create backup.sh")
    result5 = create_executable_script("backup.sh")
    print(f"Result: {'Success' if result5 else 'Failed'}\\n")


if __name__ == "__main__":
    main()
