
import os
import re
import secrets
import time
from pathlib import Path

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'jpg', 'jpeg', 'png', 'gif'}
UPLOAD_DIR = 'uploads'
def upload_file(file_data, original_filename):
    try:
        # Create uploads directory if it doesn't exist
        upload_path = Path(UPLOAD_DIR)
        upload_path.mkdir(exist_ok=True)

        # Validate file size
        if len(file_data) > MAX_FILE_SIZE:
            return "Error: File size exceeds limit"

        # Sanitize and validate filename
        sanitized_name = sanitize_filename(original_filename)
        if not sanitized_name:
            return "Error: Invalid filename"

        # Validate file extension
        extension = get_file_extension(sanitized_name)
        if extension.lower() not in ALLOWED_EXTENSIONS:
            return "Error: File type not allowed"

        # Generate unique filename
        unique_filename = generate_unique_filename(sanitized_name)
        file_path = upload_path / unique_filename

        # Prevent path traversal
        try:
            file_path = file_path.resolve()
            upload_path = upload_path.resolve()
            if not str(file_path).startswith(str(upload_path)):
                return "Error: Invalid file path"
        except Exception:
            return "Error: Invalid file path"

        # Save file securely
        with open(file_path, "wb") as f:
            f.write(file_data)

        return f"Success: File uploaded as {unique_filename}"

    except Exception as e:
        return f"Error: {str(e)}"


def sanitize_filename(filename):
    if not filename:
        return None
    return re.sub(r"[^a-zA-Z0-9._-]", "_", filename)


def get_file_extension(filename):
    if "." in filename:
        return filename.rsplit(".", 1)[1]
    return ""


def generate_unique_filename(original_name):
    extension = get_file_extension(original_name)
    name_without_ext = original_name.rsplit(".", 1)[0]
    timestamp = int(time.time() * 1000)
    random_num = secrets.randbelow(10000)
    return f"{name_without_ext}_{timestamp}_{random_num}.{extension}"


if __name__ == "__main__":
    print("=== File Upload Test Cases ===\n")

    # Test case 1: Valid text file
    test_file1 = b"Hello, World!"
    print("Test 1 - Valid text file:", upload_file(test_file1, "test.txt"))

    # Test case 2: Valid image file
    test_file2 = b"\x00" * 1024
    print("Test 2 - Valid image file:", upload_file(test_file2, "image.jpg"))

    # Test case 3: Invalid extension
    test_file3 = b"script content"
    print("Test 3 - Invalid extension:", upload_file(test_file3, "malicious.exe"))
    
    # Test case 4: Path traversal attempt
    test_file4 = b"data"
    print("Test 4 - Path traversal attempt:", upload_file(test_file4, "../../../etc/passwd.txt"))
    
    # Test case 5: Empty filename
    test_file5 = b"content"
    print("Test 5 - Empty filename:", upload_file(test_file5, ""))
