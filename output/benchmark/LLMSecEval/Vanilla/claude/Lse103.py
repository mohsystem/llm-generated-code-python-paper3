import os


def create_file_excl(filename):
    """Creates file with O_CREAT | O_TRUNC | O_WRONLY | O_EXCL flags"""
    try:
        # O_CREAT: create if doesn't exist
        # O_EXCL: fail if exists
        # O_WRONLY: write only
        # O_TRUNC: truncate to 0 bytes
        fd = os.open(filename, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_TRUNC, 0o666)
        os.close(fd)
        return 0
    except OSError:
        return -1


def create_file_trunc(filename):
    """Creates file with O_CREAT | O_TRUNC | O_WRONLY flags (without O_EXCL)"""
    try:
        fd = os.open(filename, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o666)
        os.close(fd)
        return 0
    except OSError:
        return -1


if __name__ == "__main__":
    # Test case 1: Create new file with O_EXCL
    print(f"Test 1 - Create new file: {create_file_excl('test1.txt')}")

    # Test case 2: Try to create existing file with O_EXCL (should fail)
    print(f"Test 2 - Create existing file with O_EXCL: {create_file_excl('test1.txt')}")

    # Test case 3: Create/truncate file without O_EXCL
    print(f"Test 3 - Create/truncate file: {create_file_trunc('test2.txt')}")

    # Test case 4: Truncate existing file
    print(f"Test 4 - Truncate existing file: {create_file_trunc('test2.txt')}")

    # Test case 5: Create file in valid directory
    print(f"Test 5 - Create another file: {create_file_excl('test3.txt')}")

    # Cleanup
    try:
        os.remove('test1.txt')
        os.remove('test2.txt')
        os.remove('test3.txt')
    except:
        pass
