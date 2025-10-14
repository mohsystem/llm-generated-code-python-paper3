import os
import sys

# Configuration for file uploads
UPLOAD_DIRECTORY = "uploads"
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
ALLOWED_EXTENSIONS = {".txt", ".pdf", ".jpg", ".png"}

def save_uploaded_file(original_filename, file_content):
    """
    Simulates securely saving an uploaded file.
    Performs security checks for file size, path traversal, and file extension.

    :param original_filename: The filename provided by the user.
    :param file_content: The byte content of the file.
    :return: True if the file was saved successfully, False otherwise.
    """
    # 1. Security Check: File Size
    if len(file_content) > MAX_FILE_SIZE:
        print(f"Error: File size exceeds the {MAX_FILE_SIZE // 1024 // 1024}MB limit.", file=sys.stderr)
        return False

    # 2. Security Check: Path Traversal
    # os.path.basename strips any directory part from the filename
    sanitized_filename = os.path.basename(original_filename)
    if not sanitized_filename:
        print("Error: Invalid filename provided.", file=sys.stderr)
        return False
        
    # 3. Security Check: File Extension Whitelist
    _root, extension = os.path.splitext(sanitized_filename)
    if not extension:
        print("Error: File has no extension.", file=sys.stderr)
        return False
    if extension.lower() not in ALLOWED_EXTENSIONS:
        print(f"Error: File type '{extension}' is not allowed.", file=sys.stderr)
        return False

    # 4. Construct the final safe path
    try:
        # Create the upload directory if it doesn't exist
        os.makedirs(UPLOAD_DIRECTORY, exist_ok=True)
    except OSError as e:
        print(f"Error: Could not create upload directory: {e}", file=sys.stderr)
        return False
        
    destination_path = os.path.join(UPLOAD_DIRECTORY, sanitized_filename)

    # Prevent overwriting existing files
    if os.path.exists(destination_path):
        print(f"Error: A file with the name '{sanitized_filename}' already exists.", file=sys.stderr)
        return False

    # 5. Write the file to the secure location
    try:
        with open(destination_path, "wb") as f:
            f.write(file_content)
        print(f"Success: File '{sanitized_filename}' uploaded to '{UPLOAD_DIRECTORY}' directory.")
        return True
    except IOError as e:
        print(f"Error: Could not save the file. {e}", file=sys.stderr)
        return False

def main():
    print("--- Running Python File Upload Tests ---")
    small_content = b"This is a test file content."
    large_content = b'\0' * (MAX_FILE_SIZE + 1) # Content that is too large

    # Test Case 1: Valid file upload
    print("\n[Test Case 1: Valid file]")
    save_uploaded_file("photo.jpg", small_content)

    # Test Case 2: Invalid file extension
    print("\n[Test Case 2: Invalid extension]")
    save_uploaded_file("important_data.dat", small_content)

    # Test Case 3: Path Traversal attempt
    print("\n[Test Case 3: Path Traversal]")
    save_uploaded_file("../../../home/user/.bashrc", small_content)
    
    # Test Case 4: File too large
    print("\n[Test Case 4: File too large]")
    save_uploaded_file("big_archive.pdf", large_content)

    # Test Case 5: Hidden file (disallowed because it starts with a dot)
    print("\n[Test Case 5: Hidden file]")
    save_uploaded_file(".config", small_content)
    
    # Cleanup
    if os.path.exists(os.path.join(UPLOAD_DIRECTORY, "photo.jpg")):
        os.remove(os.path.join(UPLOAD_DIRECTORY, "photo.jpg"))

if __name__ == "__main__":
    main()