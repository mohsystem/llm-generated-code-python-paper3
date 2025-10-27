
import os
import errno

def open_file_exclusive(filename):
    """\n    Opens a file with O_CREAT | O_TRUNC | O_WRONLY | O_EXCL flags\n    Creates file if it doesn't exist, fails if it exists\n    """
    try:
        # O_CREAT | O_EXCL | O_WRONLY | O_TRUNC
        fd = os.open(filename, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_TRUNC, 0o644)
        os.close(fd)
        return 0  # Success
    except OSError as e:
        return -1  # Failure

def open_file_truncate(filename):
    """\n    Opens a file with O_CREAT | O_TRUNC | O_WRONLY flags\n    Creates or truncates existing file\n    """
    try:
        # O_CREAT | O_WRONLY | O_TRUNC
        fd = os.open(filename, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o644)
        os.close(fd)
        return 0  # Success
    except OSError as e:
        return -1  # Failure

if __name__ == "__main__":
    print("Test Case 1: Create new file with exclusive flag")
    result1 = open_file_exclusive("test1.txt")
    print(f"Result: {'SUCCESS' if result1 == 0 else 'FAILED'}")

    print("\\nTest Case 2: Try to create existing file with exclusive flag (should fail)")
    result2 = open_file_exclusive("test1.txt")
    print(f"Result: {'FAILED AS EXPECTED' if result2 == -1 else 'UNEXPECTED SUCCESS'}")

    print("\\nTest Case 3: Create new file with truncate flag")
    result3 = open_file_truncate("test2.txt")
    print(f"Result: {'SUCCESS' if result3 == 0 else 'FAILED'}")

    print("\\nTest Case 4: Truncate existing file")
    result4 = open_file_truncate("test2.txt")
    print(f"Result: {'SUCCESS' if result4 == 0 else 'FAILED'}")

    print("\\nTest Case 5: Create file in subdirectory")
    os.makedirs("testdir", exist_ok=True)
    result5 = open_file_truncate("testdir/test3.txt")
    print(f"Result: {'SUCCESS' if result5 == 0 else 'FAILED'}")

    # Cleanup
    try:
        os.remove("test1.txt")
        os.remove("test2.txt")
        os.remove("testdir/test3.txt")
        os.rmdir("testdir")
    except:
        pass
