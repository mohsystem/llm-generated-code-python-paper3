import os
import stat

def upload_file(filename, content):
    """
    Handles the upload of a file by saving content to a specified filename
    in an 'uploads' directory. It creates the directory if it doesn't exist
    and sanitizes the filename to prevent path traversal attacks.

    :param filename: The desired name of the file. Path information will be stripped.
    :param content: The string content to write to the file.
    :return: True if the file was saved successfully, False otherwise.
    """
    if not filename or not isinstance(filename, str) or not content:
        print("Error: Filename or content is invalid.")
        return False

    # --- Security: Path Traversal Prevention ---
    # os.path.basename strips any leading directory components from the filename.
    sanitized_filename = os.path.basename(filename)

    # If the basename is empty or refers to the current/parent directory, it's invalid.
    if not sanitized_filename or sanitized_filename in ['.', '..']:
        print(f"Error: Invalid filename provided: '{filename}'")
        return False

    upload_dir = 'uploads'

    # Create the uploads directory if it doesn't exist.
    try:
        # exist_ok=True prevents an error if the directory already exists.
        os.makedirs(upload_dir, exist_ok=True)
    except OSError as e:
        print(f"Error creating directory '{upload_dir}': {e}")
        return False
    
    # Construct the full path to the destination file.
    destination_path = os.path.join(upload_dir, sanitized_filename)
    
    # --- Security: Final check ---
    # Ensure the resolved path is actually within our intended directory.
    # This is a strong defense against more complex attacks like symlink vulnerabilities.
    if not os.path.abspath(destination_path).startswith(os.path.abspath(upload_dir) + os.sep):
        print(f"Error: Final path check failed for '{filename}'. Attempted write outside of uploads directory.")
        return False

    # Write the content to the file.
    try:
        with open(destination_path, 'w') as f:
            f.write(content)
        print(f"Successfully saved file: '{destination_path}'")
        return True
    except IOError as e:
        print(f"Error writing to file '{destination_path}': {e}")
        return False

# Main execution block with test cases
if __name__ == "__main__":
    print("--- Python Test Cases ---")

    # Test Case 1: Valid simple filename
    upload_file("test1.txt", "This is a valid test file.")

    # Test Case 2: Another valid filename
    upload_file("my_image.jpg", "image data here")

    # Test Case 3: Path traversal attempt (should be sanitized and fail)
    upload_file("../../../etc/shadow", "malicious content")

    # Test Case 4: Absolute path attempt (should be sanitized and saved locally)
    upload_file("/var/log/syslog", "log content")

    # Test Case 5: Empty filename (should fail)
    upload_file("", "some content")
    
    print("------------------------\n")