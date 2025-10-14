import os
import re
import uuid
import shutil

# --- Configuration ---
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB
ALLOWED_EXTENSIONS = {'.txt', '.jpg', '.png', '.pdf', '.docx'}
UPLOAD_DIRECTORY = "python_uploads"

def upload_file(original_filename: str, file_content: bytes) -> str:
    """
    Securely "uploads" a file by saving it to a designated directory after security checks.

    Args:
        original_filename: The name of the file provided by the user.
        file_content: The byte content of the file.

    Returns:
        A confirmation or error message string.
    """
    # 1. Check for null or empty inputs
    if not original_filename or not file_content:
        return "Error: Invalid file name or content."

    # 2. Check file size
    if len(file_content) > MAX_FILE_SIZE_BYTES:
        return f"Error: File size exceeds the limit of {MAX_FILE_SIZE_BYTES // (1024*1024)} MB."
        
    # 3. Sanitize filename to prevent path traversal
    # os.path.basename strips any directory structure, a crucial first step
    basename = os.path.basename(original_filename)
    
    # 4. Validate file extension against a whitelist
    _, ext = os.path.splitext(basename)
    if not ext or ext.lower() not in ALLOWED_EXTENSIONS:
        return f"Error: File type is not allowed. Allowed types are: {list(ALLOWED_EXTENSIONS)}"

    # 5. Generate a unique, secure filename to prevent overwrites and conflicts
    # This also mitigates risks from weird characters the basename might still have
    unique_filename = f"{uuid.uuid4()}_{basename}"

    try:
        # 6. Create upload directory if it doesn't exist
        os.makedirs(UPLOAD_DIRECTORY, exist_ok=True)
        
        # 7. Define the destination path securely
        destination_path = os.path.join(UPLOAD_DIRECTORY, unique_filename)
        
        # Final check to prevent any symlink or other obscure path traversal
        if os.path.commonprefix((os.path.realpath(destination_path), os.path.realpath(UPLOAD_DIRECTORY))) != os.path.realpath(UPLOAD_DIRECTORY):
             return "Error: Directory traversal attempt detected."

        # 8. Write the file content
        with open(destination_path, "wb") as f:
            f.write(file_content)
        
        return f"Success: File '{basename}' uploaded as '{unique_filename}'."
    except IOError as e:
        # Log the exception server-side
        print(f"File upload failed: {e}")
        return "Error: Could not save the file."

def main():
    """Runs test cases for the file upload function."""
    print("--- Running Python File Upload Tests ---")
    if os.path.exists(UPLOAD_DIRECTORY):
        shutil.rmtree(UPLOAD_DIRECTORY)

    # Test Case 1: Successful upload of a valid text file
    valid_content1 = b"This is a simple text file."
    result1 = upload_file("mydocument.txt", valid_content1)
    print(f"Test 1 (Valid .txt): {result1}")

    # Test Case 2: Successful upload of a valid image file (simulated content)
    valid_image_content = b"\x89PNG\r\n\x1a\n"
    result2 = upload_file("photo.png", valid_image_content)
    print(f"Test 2 (Valid .png): {result2}")

    # Test Case 3: Rejected upload due to disallowed file type
    invalid_content3 = b"#!/bin/bash\necho 'pwned'"
    result3 = upload_file("malicious_script.sh", invalid_content3)
    print(f"Test 3 (Invalid extension .sh): {result3}")

    # Test Case 4: Rejected upload due to path traversal attempt in filename
    valid_content4 = b"some data"
    result4 = upload_file("../../etc/passwd", valid_content4)
    print(f"Test 4 (Path Traversal): {result4}")

    # Test Case 5: Rejected upload due to file size limit
    large_content = b'\0' * (MAX_FILE_SIZE_BYTES + 1)
    result5 = upload_file("largefile.docx", large_content)
    print(f"Test 5 (File too large): {result5}")
    
    # Clean up the created directory
    if os.path.exists(UPLOAD_DIRECTORY):
        shutil.rmtree(UPLOAD_DIRECTORY)
    print("--------------------------------------\n")


if __name__ == "__main__":
    main()