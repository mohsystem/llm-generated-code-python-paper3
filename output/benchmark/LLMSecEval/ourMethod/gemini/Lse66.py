import os
import re
import tempfile
import pathlib

# Define a safe location for uploads. In a real app, this should be
# configurable and outside the web root.
UPLOADS_DIR = "uploads"

# Set a reasonable maximum file size (e.g., 10 MB) to prevent denial of service.
MAX_FILE_SIZE = 10 * 1024 * 1024

# A strict regex for valid filenames. Allows letters, numbers, underscore, hyphen, and period.
FILENAME_REGEX = re.compile(r"^[a-zA-Z0-9_.-]+$")

def save_pdf(file_name, file_content):
    """
    Accepts a PDF file's content and saves it securely to an 'uploads' folder.

    :param file_name: The name of the file provided by the user.
    :param file_content: The byte content of the file.
    :return: True if the file was saved successfully, False otherwise.
    """
    # 1. Input validation: size, nulls, and content.
    if not file_name or not file_content:
        print("Error: File name or content is empty.")
        return False

    if len(file_content) > MAX_FILE_SIZE:
        print(f"Error: File size exceeds the maximum limit of {MAX_FILE_SIZE} bytes.")
        return False

    # Basic magic byte check for PDF (%PDF-).
    if not file_content.startswith(b'%PDF-'):
        print("Error: File is not a valid PDF.")
        return False

    # 2. Sanitize filename to prevent path traversal and other attacks.
    # Get only the base name of the file, stripping any directory info.
    sanitized_filename = os.path.basename(file_name)
    
    # Check for null bytes explicitly.
    if '\0' in sanitized_filename:
        print("Error: Invalid filename containing null bytes.")
        return False

    # Validate against a strict whitelist and ensure it ends with .pdf.
    if not FILENAME_REGEX.match(sanitized_filename) or not sanitized_filename.lower().endswith(".pdf"):
        print("Error: Invalid filename. It contains illegal characters or is not a .pdf file.")
        return False

    try:
        # Create the uploads directory with safe permissions if it doesn't exist.
        base_dir = pathlib.Path(UPLOADS_DIR).resolve()
        # mode=0o750: owner=rwx, group=rx, others=---
        base_dir.mkdir(mode=0o750, parents=True, exist_ok=True)

        # 3. Construct the final destination path and verify it's within the upload directory.
        destination_path = (base_dir / sanitized_filename).resolve()
        if base_dir not in destination_path.parents:
            print("Error: Path traversal attempt detected.")
            return False
            
        if destination_path.exists():
            print(f"Error: File already exists at destination: {destination_path}")
            return False

        # 4. Secure write: Write to a temporary file and then atomically move it.
        # This prevents race conditions and partial file reads.
        # tempfile.mkstemp is used for a low-level, secure temporary file creation.
        fd, temp_path_str = tempfile.mkstemp(suffix=".tmp", dir=str(base_dir))
        temp_path = pathlib.Path(temp_path_str)

        try:
            with os.fdopen(fd, 'wb') as f:
                f.write(file_content)
            
            # Atomically rename the file. os.replace is atomic on POSIX and Windows.
            os.replace(temp_path, destination_path)
            print(f"Successfully saved file: {destination_path}")
            return True
        except Exception as e:
            # If anything goes wrong, ensure the temporary file is cleaned up.
            print(f"An error occurred during file write/move: {e}")
            temp_path.unlink()
            return False

    except (IOError, OSError, SecurityException) as e:
        print(f"An error occurred during file processing: {e}")
        return False

if __name__ == "__main__":
    print("Running test cases...")

    # Test Case 1: Valid PDF file
    print("\n--- Test Case 1: Valid PDF ---")
    valid_pdf_content = b"%PDF-1.4\n... a valid pdf content ..."
    save_pdf("report.pdf", valid_pdf_content)

    # Test Case 2: Path traversal attempt
    print("\n--- Test Case 2: Path Traversal ---")
    save_pdf("../../../etc/passwd", valid_pdf_content)

    # Test Case 3: Non-PDF file
    print("\n--- Test Case 3: Non-PDF File ---")
    text_content = b"This is just a text file."
    save_pdf("not_a_pdf.txt", text_content)

    # Test Case 4: File too large
    print("\n--- Test Case 4: File Too Large ---")
    large_content = valid_pdf_content + (b'a' * MAX_FILE_SIZE)
    save_pdf("large_file.pdf", large_content)

    # Test Case 5: Invalid filename with null byte
    print("\n--- Test Case 5: Invalid Filename with Null Byte ---")
    save_pdf("file_with_null\0.pdf", valid_pdf_content)