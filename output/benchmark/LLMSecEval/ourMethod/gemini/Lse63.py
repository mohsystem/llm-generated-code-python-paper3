import os
import stat
import sys
import tempfile
from pathlib import Path

MAX_FILE_SIZE = 16 * 1024 * 1024  # 16 MB limit

def process_file(input_path: str, output_path: str) -> bool:
    """
    Reads a file, calculates its checksum, and writes the results to another file.
    Follows secure file handling practices.
    """
    fd = -1
    try:
        # 1. Open the file securely, without following symlinks.
        # os.O_NOFOLLOW is not available on Windows, but os.open doesn't follow them there.
        open_flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0)
        fd = os.open(input_path, open_flags)

        # 2. Validate the opened file handle (descriptor).
        stat_info = os.fstat(fd)

        if not stat.S_ISREG(stat_info.st_mode):
            print(f"Error: Input path '{input_path}' is not a regular file.", file=sys.stderr)
            return False

        if stat_info.st_size > MAX_FILE_SIZE:
            print(f"Error: File size {stat_info.st_size} exceeds maximum limit of {MAX_FILE_SIZE} bytes.", file=sys.stderr)
            return False

        # 3. Read the contents using the validated file descriptor.
        content = os.read(fd, stat_info.st_size)
        bytes_read = len(content)

    except FileNotFoundError:
        print(f"Error: Input file not found at '{input_path}'.", file=sys.stderr)
        return False
    except OSError as e:
        print(f"Error opening or reading file '{input_path}': {e}", file=sys.stderr)
        return False
    finally:
        if fd != -1:
            os.close(fd)
            
    # 4. Calculate checksum.
    checksum = sum(content)

    # 5. Write results to a temporary file and then atomically rename.
    temp_path = ""
    try:
        output_path_obj = Path(output_path)
        output_dir = output_path_obj.parent
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Use NamedTemporaryFile to create a temporary file in the same directory
        with tempfile.NamedTemporaryFile('w', dir=output_dir, delete=False, encoding='utf-8', prefix="checksum_", suffix=".tmp") as temp_f:
            temp_path = temp_f.name
            temp_f.write(f"Bytes read: {bytes_read}\n")
            temp_f.write(f"Checksum: {checksum}\n")
        
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, output_path)
    except Exception as e:
        print(f"Error writing to output file '{output_path}': {e}", file=sys.stderr)
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)
        return False

    return True

def main():
    """Main function with test cases."""
    temp_dir = Path(tempfile.gettempdir()) / "lse63_py_tests"
    temp_dir.mkdir(exist_ok=True)
    
    print(f"Running tests in: {temp_dir}")
    
    test_cases = [
        {"name": "empty_file", "content": b"", "succeed": True},
        {"name": "hello_file", "content": b"hello world", "succeed": True},
        {"name": "binary_file", "content": b"\xff\xff\x00\x01", "succeed": True},
        {"name": "null_bytes_file", "content": b"\0\0\0\0", "succeed": True},
        {"name": "non_existent_file", "content": None, "succeed": False},
    ]

    for i, case in enumerate(test_cases):
        print(f"\n--- Test Case {i+1}: {case['name']} ---")
        input_file = temp_dir / f"{case['name']}.txt"
        output_file = temp_dir / f"{case['name']}.out"
        
        try:
            if input_file.exists(): input_file.unlink()
            if output_file.exists(): output_file.unlink()
            if case['content'] is not None:
                input_file.write_bytes(case['content'])
        except OSError as e:
            print(f"Test setup failed: {e}", file=sys.stderr)
            continue
            
        print(f"Input: {input_file}, Output: {output_file}")
        
        result = process_file(str(input_file), str(output_file))
        
        print(f"Execution result: {'SUCCESS' if result else 'FAILURE'}")
        print(f"Expected result:  {'SUCCESS' if case['succeed'] else 'FAILURE'}")

        if result == case['succeed']:
            print("Test PASSED.")
            if result:
                print("Output content:\n" + output_file.read_text().strip())
        else:
            print("Test FAILED.")
            
        try:
            if input_file.exists(): input_file.unlink()
            if output_file.exists(): output_file.unlink()
        except OSError:
            pass
        
    try:
        if os.path.exists(temp_dir):
            os.rmdir(temp_dir)
            print(f"\nCleaned up test directory: {temp_dir}")
    except OSError:
        print(f"\nCould not remove test directory (might not be empty): {temp_dir}")


if __name__ == "__main__":
    main()