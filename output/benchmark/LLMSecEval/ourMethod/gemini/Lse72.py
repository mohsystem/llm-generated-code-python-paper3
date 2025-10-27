import os
import pathlib
import sys

def upload_file(filename: str, content: bytes) -> bool:
    """
    Securely uploads a file to a designated 'uploads' directory.
    The 'uploads' directory is created in the same directory as this script.
    This function prevents path traversal attacks and race conditions (TOCTOU).

    Args:
        filename: The name of the file to be saved. This will be sanitized.
        content: The byte content of the file.

    Returns:
        True if the upload was successful, False otherwise.
    """
    if not filename or not isinstance(filename, str) or not isinstance(content, bytes):
        print("Error: Filename must be a non-empty string and content must be bytes.", file=sys.stderr)
        return False

    try:
        # Define the base directory for uploads, relative to the script location.
        # Fallback to current working directory if __file__ is not available.
        try:
            base_dir = pathlib.Path(__file__).parent.resolve()
        except NameError:
            base_dir = pathlib.Path.cwd().resolve()
            
        uploads_dir = base_dir / "uploads"

        # Create the directory if it doesn't exist.
        uploads_dir.mkdir(exist_ok=True)
        
        if not uploads_dir.is_dir():
            print(f"Error: '{uploads_dir}' exists but is not a directory.", file=sys.stderr)
            return False

        # Sanitize the filename to prevent path traversal.
        # os.path.basename() securely extracts the filename part.
        sanitized_filename = os.path.basename(filename)
        if not sanitized_filename:
            print("Error: Filename is empty after sanitization.", file=sys.stderr)
            return False

        # Construct the final destination path.
        dest_path = uploads_dir / sanitized_filename
        
        # Security Check: Resolve both paths and ensure the destination is
        # strictly within the intended uploads directory. This is a robust defense
        # against complex path traversal attacks.
        if dest_path.resolve().parent != uploads_dir.resolve():
            print("Error: Path traversal attempt detected.", file=sys.stderr)
            return False

        # Securely open the file for writing.
        # os.O_CREAT | os.O_EXCL: Atomically create the file; fail if it exists.
        # os.O_WRONLY: Write-only mode.
        # This approach prevents TOCTOU (Time-of-Check to Time-of-Use) vulnerabilities.
        try:
            # 0o600 sets permissions to read/write for owner only.
            fd = os.open(dest_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as f:
                f.write(content)
            print(f"Successfully uploaded file to: {dest_path.resolve()}")
            return True
        except FileExistsError:
            print(f"Error: File already exists: {dest_path}", file=sys.stderr)
            return False
        except OSError as e:
            print(f"Error writing to file: {e}", file=sys.stderr)
            return False

    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        return False


if __name__ == "__main__":
    print("--- Running Test Cases ---")

    # Test Case 1: Valid upload
    print("\n--- Test Case 1: Valid upload ---")
    upload_file("test1.txt", b"This is a valid test file.")

    # Test Case 2: Path traversal attempt
    print("\n--- Test Case 2: Path traversal attempt ---")
    upload_file("../test2.txt", b"This should fail.")
    upload_file("subdir/../../test2_b.txt", b"This should also fail.")

    # Test Case 3: Empty/null inputs
    print("\n--- Test Case 3: Empty/null inputs ---")
    upload_file("", b"Empty filename.")
    upload_file(None, b"Null filename.")
    upload_file("test3.txt", None)

    # Test Case 4: Re-uploading the same file (should fail)
    print("\n--- Test Case 4: Re-uploading same file ---")
    upload_file("test1.txt", b"This should fail because it already exists.")

    # Test Case 5: Filename with path components (should be sanitized)
    print("\n--- Test Case 5: Filename with path components ---")
    upload_file("/etc/passwd", b"This content should not be written to /etc/passwd")
    upload_file("C:\\Users\\test\\myfile.txt", b"This should be saved as myfile.txt in uploads")

    print("\n--- Test Cases Finished ---")