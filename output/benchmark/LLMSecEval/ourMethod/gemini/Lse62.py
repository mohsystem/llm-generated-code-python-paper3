import os
import sys
import stat

# Define a reasonable maximum file size to prevent resource exhaustion.
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16 MB

def process_file(input_path: str, output_path: str) -> bool:
    """
    Reads a file, calculates its checksum, and writes the results to another file.
    This function follows secure file handling practices: open-then-validate.
    """
    input_fd = -1
    output_fd = -1

    try:
        # --- Read Input File ---
        # Open the resource first, preventing symlink following using os.O_NOFOLLOW.
        try:
            # os.O_CLOEXEC prevents descriptor leakage to child processes.
            open_flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0)
            input_fd = os.open(input_path, open_flags)
        except FileNotFoundError:
            print(f"Error: Input file not found: {input_path}", file=sys.stderr)
            return False
        except OSError as e:
            print(f"Error opening input file '{input_path}': {e}", file=sys.stderr)
            return False

        # Validate the already-opened handle.
        try:
            f_stat = os.fstat(input_fd)
        except OSError as e:
            print(f"Error getting file stats for '{input_path}': {e}", file=sys.stderr)
            return False

        # Reject if not a regular file or if size exceeds the policy limit.
        if not stat.S_ISREG(f_stat.st_mode):
            print(f"Error: Input '{input_path}' is not a regular file.", file=sys.stderr)
            return False
        
        file_size = f_stat.st_size
        if file_size > MAX_FILE_SIZE:
            print(f"Error: Input file '{input_path}' size exceeds the limit of {MAX_FILE_SIZE} bytes.", file=sys.stderr)
            return False

        # Read the file content into a buffer.
        buffer = os.read(input_fd, file_size) if file_size > 0 else b''
        if len(buffer) != file_size:
            print(f"Error: Incomplete read from '{input_path}'. Expected {file_size}, got {len(buffer)}.", file=sys.stderr)
            return False

        # --- Calculate Checksum ---
        checksum = sum(buffer)
        # If checksum is 0, the buffer is empty (file_size was 0).

        # --- Write Output File ---
        # Create output file securely with restrictive permissions.
        # os.O_EXCL ensures the call fails if the file already exists (atomic creation).
        try:
            # Mode 0o600 means read/write for owner only.
            write_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_CLOEXEC', 0)
            output_fd = os.open(output_path, write_flags, 0o600)
        except FileExistsError:
            print(f"Error: Output file already exists: {output_path}", file=sys.stderr)
            return False
        except OSError as e:
            print(f"Error creating output file '{output_path}': {e}", file=sys.stderr)
            return False

        output_content = f"Bytes read: {len(buffer)}\nChecksum: {checksum}\n".encode('utf-8')
        bytes_written = os.write(output_fd, output_content)

        if bytes_written != len(output_content):
            print(f"Error: Incomplete write to '{output_path}'.", file=sys.stderr)
            return False
        
        print(f"Successfully processed '{input_path}', results in '{output_path}'")
        return True

    finally:
        if input_fd != -1:
            os.close(input_fd)
        if output_fd != -1:
            os.close(output_fd)


def run_test(name: str, content: bytes, should_succeed: bool, create_file: bool = True):
    print(f"--- Test Case: {name} ---")
    input_file = "test_input.txt"
    output_file = "test_output.txt"

    if os.path.exists(input_file): os.remove(input_file)
    if os.path.exists(output_file): os.remove(output_file)

    if create_file:
        try:
            with open(input_file, 'wb') as f:
                if content is not None:
                    f.write(content)
        except IOError as e:
            print(f"Failed to create test input file: {e}", file=sys.stderr)
            return
    else:
        print("Testing with non-existent input file.")
        
    result = process_file(input_file, output_file)
    
    if should_succeed:
        assert result, "FAIL: Process failed unexpectedly."
        print("PASS: Process succeeded as expected.")
    else:
        assert not result, "FAIL: Process succeeded unexpectedly."
        print("PASS: Process failed as expected.")

    if os.path.exists(input_file): os.remove(input_file)
    if os.path.exists(output_file): os.remove(output_file)
    print()


if __name__ == '__main__':
    run_test("Normal file", b"Hello World!", True)
    run_test("Empty file", b"", True)
    run_test("File with null bytes", b"a\0b\0c", True)
    run_test("Non-existent file", None, False, create_file=False)

    print("--- Test Case: Output file exists ---")
    input_f = "test_input.txt"
    output_f = "test_output.txt"
    if os.path.exists(input_f): os.remove(input_f)
    if os.path.exists(output_f): os.remove(output_f)
    with open(input_f, 'w'): pass
    with open(output_f, 'w'): pass
    
    res = process_file(input_f, output_f)
    assert not res, "FAIL: Process succeeded but should have failed."
    print("PASS: Process failed as expected because output file exists.")
    
    if os.path.exists(input_f): os.remove(input_f)
    if os.path.exists(output_f): os.remove(output_f)
    print()