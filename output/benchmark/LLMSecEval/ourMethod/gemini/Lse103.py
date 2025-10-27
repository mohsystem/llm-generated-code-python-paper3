import os
import sys

def demonstrate_open(path, flags, description):
    """
    Demonstrates the os.open() function with various flags.
    """
    print(f"--- Test: {description} ---")
    print(f"Attempting to open '{path}'...")
    
    fd = -1
    try:
        # The mode argument (e.g., 0o600) is required when O_CREAT is used.
        mode = 0o600
        fd = os.open(path, flags, mode)
        print(f"Success: File opened with descriptor {fd}.")
        
        if "Write data" in description:
            content = b"hello world"
            bytes_written = os.write(fd, content)
            print(f"Successfully wrote {bytes_written} bytes to file.")

    except FileExistsError as e:
        print(f"Failed as expected: File already exists. {e}", file=sys.stderr)
    except FileNotFoundError as e:
        print(f"Failed as expected: File does not exist. {e}", file=sys.stderr)
    except OSError as e:
        print(f"An OS error occurred: {e}", file=sys.stderr)
    finally:
        if fd != -1:
            try:
                os.close(fd)
            except OSError as e:
                print(f"Error closing file descriptor: {e}", file=sys.stderr)
    print()

def main():
    """
    Runs test cases for demonstrate_open.
    """
    test_file = "py_testfile.txt"
    non_existent_file = "py_non_existent.txt"

    # Initial cleanup
    for f in [test_file, non_existent_file]:
        try:
            os.remove(f)
        except FileNotFoundError:
            pass

    # Test 1: O_WRONLY | O_CREAT | O_EXCL - Atomically create a new file. Fails if it exists.
    print("1) Demonstrating O_EXCL (exclusive creation)")
    flags1 = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    demonstrate_open(test_file, flags1, "O_WRONLY | O_CREAT | O_EXCL (exclusive create)")

    # Test 2: Try to create it again with O_EXCL. Must fail.
    print("2) Demonstrating O_EXCL on an existing file")
    flags2 = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    demonstrate_open(test_file, flags2, "O_WRONLY | O_CREAT | O_EXCL (on existing file)")

    # Test 3: Write some data to the file to demonstrate truncation later.
    print("3) Writing data to the file")
    flags3 = os.O_WRONLY | os.O_TRUNC
    demonstrate_open(test_file, flags3, "Write data to existing file")

    # Test 4: O_WRONLY | O_CREAT | O_TRUNC - Create if not exists, or truncate if it does.
    print("4) Demonstrating O_TRUNC on an existing file")
    flags4 = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    demonstrate_open(test_file, flags4, "O_WRONLY | O_CREAT | O_TRUNC (on existing file)")

    # Test 5: O_WRONLY on a non-existent file (without O_CREAT). Must fail.
    print("5) Demonstrating opening a non-existent file without O_CREAT")
    flags5 = os.O_WRONLY
    demonstrate_open(non_existent_file, flags5, "O_WRONLY (on non-existent file)")
    
    # Final cleanup
    try:
        os.remove(test_file)
    except FileNotFoundError:
        pass


if __name__ == "__main__":
    main()