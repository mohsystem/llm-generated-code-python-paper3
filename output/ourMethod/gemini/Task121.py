import os
import shutil
import tempfile
import pathlib
import sys
from typing import Union

def upload_file(source_file_path: Union[str, pathlib.Path], 
                destination_dir: Union[str, pathlib.Path], 
                new_file_name: str) -> bool:
    """
    Securely "uploads" a file by copying it from a source path to a destination directory.
    This implementation prevents path traversal and uses an atomic move to mitigate TOCTOU vulnerabilities.

    :param source_file_path: The path to the file to be uploaded.
    :param destination_dir: The directory where the file will be saved.
    :param new_file_name: The name for the new file. Must not contain path separators.
    :return: True on success, False on failure.
    """
    # Rule #6: Validate inputs
    if not all([source_file_path, destination_dir, new_file_name]):
        print("Error: Input paths cannot be null or empty.", file=sys.stderr)
        return False

    # Rule #9: Prevent path traversal by validating the filename.
    # It must be a simple name, not a path.
    if os.path.sep in new_file_name or (os.altsep and os.altsep in new_file_name) or ".." in new_file_name:
        print(f"Error: Invalid filename '{new_file_name}'. It must not contain path elements.", file=sys.stderr)
        return False

    temp_file_path_str = ""
    try:
        source_path = pathlib.Path(source_file_path)
        dest_dir_path = pathlib.Path(destination_dir)

        # Further validation of paths
        if not source_path.is_file():
            print(f"Error: Source '{source_path}' does not exist or is not a regular file.", file=sys.stderr)
            return False
        
        if not dest_dir_path.is_dir():
            print(f"Error: Destination '{dest_dir_path}' does not exist or is not a directory.", file=sys.stderr)
            return False

        # Rule #9: Resolve paths to their canonical form to prevent traversal attacks.
        canonical_dest_dir = dest_dir_path.resolve()
        final_dest_path = canonical_dest_dir / new_file_name

        # Double-check that the final path's parent is the intended directory.
        if final_dest_path.parent != canonical_dest_dir:
            print(f"Error: Path traversal attempt detected for filename '{new_file_name}'.", file=sys.stderr)
            return False

        # Rule #3: Mitigate TOCTOU by writing to a temporary file and then moving atomically.
        # Create a temporary file securely in the destination directory.
        fd, temp_file_path_str = tempfile.mkstemp(prefix=".tmp_", dir=canonical_dest_dir)

        with open(source_path, 'rb') as src_f, os.fdopen(fd, 'wb') as temp_f:
            # Rule #1, #2: shutil.copyfileobj copies in chunks with a buffer.
            shutil.copyfileobj(src_f, temp_f)
        
        # Atomically rename the temp file to the final name.
        # os.rename is atomic on most POSIX systems if src and dst are on the same filesystem.
        os.rename(temp_file_path_str, final_dest_path)
        print(f"File uploaded successfully to: {final_dest_path}")
        return True

    except (IOError, OSError, Exception) as e:
        # Rule #15: Catch and handle exceptions
        print(f"An error occurred: {e}", file=sys.stderr)
        # Cleanup the temporary file if it was created
        if temp_file_path_str and os.path.exists(temp_file_path_str):
            os.remove(temp_file_path_str)
        return False


def main():
    """Main function for testing."""
    test_root = None
    try:
        # Setup test environment
        test_root = pathlib.Path(tempfile.mkdtemp(prefix="test_root_py_"))
        source_dir = test_root / "sources"
        upload_dir = test_root / "uploads"
        source_dir.mkdir()
        upload_dir.mkdir()
        
        source_file = source_dir / "testfile.txt"
        source_file.write_text("This is a test file.")

        print(f"Test environment created in: {test_root}")
        print(f"Source file: {source_file}")
        print(f"Upload directory: {upload_dir}")
        print("------------------------------------------")

        # Test Case 1: Successful upload
        print("Test Case 1: Successful upload")
        success1 = upload_file(source_file, upload_dir, "newfile.txt")
        print(f"Result: {'SUCCESS' if success1 else 'FAILURE'}")
        print("------------------------------------------")

        # Test Case 2: Path traversal attempt
        print("Test Case 2: Path traversal attempt with '../evil.txt'")
        success2 = upload_file(source_file, upload_dir, "../evil.txt")
        print(f"Result: {'SUCCESS' if success2 else 'FAILURE'}")
        print("------------------------------------------")

        # Test Case 3: Source file does not exist
        print("Test Case 3: Source file does not exist")
        success3 = upload_file("nonexistent.txt", upload_dir, "anotherfile.txt")
        print(f"Result: {'SUCCESS' if success3 else 'FAILURE'}")
        print("------------------------------------------")

        # Test Case 4: Destination directory does not exist
        print("Test Case 4: Destination directory does not exist")
        success4 = upload_file(source_file, upload_dir / "nonexistent", "anotherfile.txt")
        print(f"Result: {'SUCCESS' if success4 else 'FAILURE'}")
        print("------------------------------------------")

        # Test Case 5: Filename contains a subdirectory
        print("Test Case 5: Filename contains a subdirectory 'subdir/file.txt'")
        success5 = upload_file(source_file, upload_dir, f"subdir{os.path.sep}file.txt")
        print(f"Result: {'SUCCESS' if success5 else 'FAILURE'}")
        print("------------------------------------------")

    finally:
        # Cleanup
        if test_root and test_root.exists():
            shutil.rmtree(test_root)
            print(f"Cleaned up test environment: {test_root}")

if __name__ == "__main__":
    main()