import os
import stat

SAFE_DIR = "/safe/"
MAX_FILE_SIZE = 1024 * 1024  # 1 MiB

def read_file_from_safe_directory(filename):
    """
    Reads a file from a secure directory, preventing path traversal and other attacks.
    
    :param filename: The name of the file to read. Must not contain path separators.
    :return: The content of the file as a string.
    :raises ValueError: if the filename is invalid.
    :raises IOError: if the file cannot be read or violates security checks.
    """
    # Rule #3: Validate input
    if not filename or '/' in filename or '\\' in filename:
        raise ValueError("Invalid filename: cannot be empty or contain path separators.")
    
    dir_fd = -1
    file_fd = -1

    try:
        # Get a file descriptor for the safe base directory
        dir_fd = os.open(SAFE_DIR, os.O_RDONLY | os.O_DIRECTORY)

        # Rule #2: Open-then-validate pattern to avoid TOCTOU
        # os.O_NOFOLLOW prevents following symbolic links
        # The operation is relative to dir_fd, preventing escape from SAFE_DIR
        try:
            file_fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
        except FileNotFoundError:
             raise IOError(f"File not found: {filename}")
        except IsADirectoryError:
             raise IOError(f"Path is a directory, not a file: {filename}")

        # Validate the opened handle (file descriptor)
        stat_info = os.fstat(file_fd)

        # Rule #1: Ensure it's a regular file, not a directory, symlink, etc.
        if not stat.S_ISREG(stat_info.st_mode):
            raise IOError("Not a regular file.")

        # Rule #5: Check file size against a limit
        if stat_info.st_size > MAX_FILE_SIZE:
            raise IOError(f"File size exceeds limit of {MAX_FILE_SIZE} bytes.")

        # Read from the validated handle
        with os.fdopen(file_fd, 'r', encoding='utf-8') as f:
            file_fd = -1  # fdopen now owns the descriptor
            return f.read()

    finally:
        # Rule #9: Ensure resources are cleaned up
        if file_fd != -1:
            os.close(file_fd)
        if dir_fd != -1:
            os.close(dir_fd)

def main():
    """
    To run these test cases, you need to set up the environment.
    You may need root permissions to create /safe.

    sudo mkdir -p /safe/subdir
    sudo sh -c 'echo "This is a valid file." > /safe/valid_file.txt'
    sudo sh -c 'echo "This is outside the safe dir." > /outside_file.txt'
    sudo ln -s /safe/valid_file.txt /safe/symlink_to_valid
    sudo chmod 600 /safe/valid_file.txt
    """
    test_filenames = [
        "valid_file.txt",                # 1. Should succeed
        "non_existent_file.txt",         # 2. Should fail (file not found)
        "../outside_file.txt",           # 3. Should fail (invalid filename)
        "/etc/passwd",                   # 4. Should fail (invalid filename)
        "symlink_to_valid",              # 5. Should fail (is a symlink, O_NOFOLLOW)
        "subdir"                         # 6. Should fail (is a directory)
    ]

    for filename in test_filenames:
        print(f"--- Testing: {filename} ---")
        try:
            content = read_file_from_safe_directory(filename)
            print(f"Success! Read {len(content)} characters.")
            # print(f"Content: {content}")
        except (IOError, ValueError, OSError) as e:
            print(f"Failed as expected: {e}")

if __name__ == "__main__":
    main()