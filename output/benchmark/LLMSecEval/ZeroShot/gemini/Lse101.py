import os
import sys

def write_secure_file(file_name, content):
    """
    Creates a file and writes content to it with secure permissions.
    On POSIX systems, this function atomically creates the file with permissions
    set to owner-only read/write (600).
    
    Args:
        file_name (str): The name of the file to write to.
        content (str): The string content to write to the file.
        
    Returns:
        bool: True on success, False on failure.
    """
    if not isinstance(file_name, str) or not file_name or not isinstance(content, str):
        print("Error: Invalid file name or content provided.", file=sys.stderr)
        return False

    try:
        # On POSIX systems, os.open is preferred as it can set permissions atomically.
        # The mode 0o600 means read/write for the owner only (-rw-------).
        # O_WRONLY: write-only
        # O_CREAT: create if it doesn't exist
        # O_TRUNC: truncate to zero length if it exists
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        mode = 0o600
        
        # The 'with' statement ensures the file descriptor is closed.
        fd = os.open(file_name, flags, mode)
        with os.fdopen(fd, 'w') as f:
            f.write(content)
        
        return True
    except (IOError, OSError, TypeError) as e:
        # TypeError can be raised on Windows if mode is passed
        # A simple fallback for non-POSIX systems
        try:
             with open(file_name, 'w') as f:
                f.write(content)
             return True
        except (IOError, OSError) as e_fallback:
             print(f"Error writing to file '{file_name}': {e_fallback}", file=sys.stderr)
             return False

def main():
    """Main function with test cases."""
    print("--- Python Test Cases ---")
    
    test_cases = [
        ("important_config", "important_config"),
        ("user_settings.conf", "user=admin;level=5;"),
        ("api_key.txt", "ABC-123-DEF-456"),
        ("log_file.log", "Initial log entry."),
        ("", "some content") # Invalid filename
    ]

    for i, (filename, content) in enumerate(test_cases, 1):
        print(f"Running test case {i} for file: '{filename}'")
        success = write_secure_file(filename, content)
        if success:
            print(" -> Success.")
        else:
            print(" -> Failed.")
        print()

if __name__ == "__main__":
    main()