import os
import pathlib
import tempfile
import sys
from typing import Union

UPLOAD_DIR_NAME = "uploads"

def upload_file(original_filename: str, content: bytes) -> str:
    """
    Simulates uploading a file by saving its content to a designated upload directory.

    :param original_filename: The requested filename from the user.
    :param content: The file content as bytes.
    :return: A confirmation or error message.
    """
    if not original_filename:
        return "Error: Filename cannot be empty."

    try:
        upload_dir = pathlib.Path(UPLOAD_DIR_NAME).resolve(strict=True)
    except FileNotFoundError:
        return f"Error: Upload directory '{UPLOAD_DIR_NAME}' does not exist."

    if not upload_dir.is_dir():
        return f"Error: Upload path '{upload_dir}' is not a directory."

    # Rule #9: Sanitize filename to prevent directory traversal.
    # pathlib.Path().name extracts the final component of the path.
    sanitized_filename = pathlib.Path(original_filename).name
    if not sanitized_filename or sanitized_filename in ('.', '..'):
         return "Error: Invalid filename provided."

    # Rule #9: Ensure the final path resolves within the expected directory.
    final_path = (upload_dir / sanitized_filename)
    
    # After resolving, check that the final path is truly inside the upload directory.
    # This is a critical security check against various path manipulation attacks.
    try:
        # relative_to raises ValueError if the path is not within the directory
        final_path.resolve().relative_to(upload_dir.resolve())
    except (ValueError, FileNotFoundError): # FileNotFoundError for broken symlinks
        return "Error: Path traversal attempt detected."

    if final_path.exists():
        return f"Error: File '{sanitized_filename}' already exists."
        
    # Rule #3: Mitigate TOCTOU by writing to a temporary file and then renaming.
    fd: int = -1
    temp_file_path: Union[str, bytes] = ""
    try:
        # Create a temporary file securely in the upload directory.
        fd, temp_file_path = tempfile.mkstemp(prefix="upload-", suffix=".tmp", dir=upload_dir)
        
        # Rule #1, #2: Write content to the temporary file.
        with os.fdopen(fd, 'wb') as temp_file:
            temp_file.write(content)
        
        # Atomically rename the file.
        os.rename(temp_file_path, final_path)
        temp_file_path = "" # Prevent deletion in finally block
        
        return f"Success: File '{sanitized_filename}' uploaded successfully."

    except (IOError, OSError) as e:
        return f"Error: Could not save file. {e}"
    finally:
        # Ensure temporary file is cleaned up if it still exists
        if temp_file_path and os.path.exists(temp_file_path):
            os.remove(temp_file_path)

def main():
    """Main function with test cases."""
    upload_dir = pathlib.Path(UPLOAD_DIR_NAME)
    try:
        upload_dir.mkdir(exist_ok=True)
        print(f"Upload directory ready at: {upload_dir.resolve()}")
    except OSError as e:
        print(f"Fatal: Could not create upload directory. {e}", file=sys.stderr)
        return

    sample_content = b"This is the file content."

    print("\n--- Running Test Cases ---")
    
    print("1. Valid filename 'test1.txt':")
    print(f"   {upload_file('test1.txt', sample_content)}")

    print("2. Filename with spaces 'my document.pdf':")
    print(f"   {upload_file('my document.pdf', sample_content)}")

    print("3. Path traversal attempt '../secret.txt':")
    print(f"   {upload_file('../secret.txt', sample_content)}")

    absolute_path = os.path.abspath(os.path.join(os.path.sep, 'etc', 'passwd'))
    print(f"4. Absolute path attempt '{absolute_path}':")
    print(f"   {upload_file(absolute_path, sample_content)}")
    
    print("5. Empty filename '':")
    print(f"   {upload_file('', sample_content)}")

    print("\n--- Cleaning up created files ---")
    try:
        if (upload_dir / "test1.txt").exists():
            (upload_dir / "test1.txt").unlink()
        if (upload_dir / "my document.pdf").exists():
            (upload_dir / "my document.pdf").unlink()
        upload_dir.rmdir()
        print("Cleanup successful.")
    except OSError as e:
        print(f"Cleanup failed: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()