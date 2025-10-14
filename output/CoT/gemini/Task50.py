import os
import uuid

# Define a safe directory for uploads.
UPLOAD_DIRECTORY = "uploads_python"
# Define a maximum file size to prevent denial-of-service attacks (e.g., 5MB).
MAX_FILE_SIZE = 5 * 1024 * 1024

def upload_file(original_file_name, file_content):
    """
    Simulates uploading a file to the server.

    :param original_file_name: The name of the file provided by the user.
    :param file_content: The binary content of the file.
    :return: A confirmation or error message.
    """
    # Security: Check for null or empty inputs
    if not original_file_name or not original_file_name.strip():
        return "Error: File name cannot be empty."
    if not file_content:
        return "Error: File content cannot be empty."

    # Security: Check file size
    if len(file_content) > MAX_FILE_SIZE:
        return f"Error: File size exceeds the {MAX_FILE_SIZE // (1024 * 1024)}MB limit."

    try:
        # Security: Prevent path traversal attacks.
        # os.path.basename() strips any directory part from the name.
        # e.g., "../../etc/passwd" becomes "passwd"
        sanitized_file_name = os.path.basename(original_file_name)

        if not sanitized_file_name:
            return "Error: Invalid file name provided."

        # Security: Generate a unique filename to prevent overwrites.
        _, file_extension = os.path.splitext(sanitized_file_name)
        unique_file_name = f"{uuid.uuid4()}{file_extension}"

        # Create the upload directory if it doesn't exist
        os.makedirs(UPLOAD_DIRECTORY, exist_ok=True)

        # Construct the final, safe destination path
        destination_path = os.path.join(UPLOAD_DIRECTORY, unique_file_name)
        
        # Write the file using a 'with' statement to ensure it's properly closed
        with open(destination_path, "wb") as f:
            f.write(file_content)

        return f"Success: File '{original_file_name}' uploaded as '{unique_file_name}'."

    except IOError as e:
        # Log the exception in a real application
        return f"Error: Could not save the file. {e}"
    except Exception as e:
        # Catch any other unexpected errors
        return f"Error: An unexpected error occurred. {e}"

def main():
    """ Main function with test cases """
    print("--- Running Python Test Cases ---")

    # Test Case 1: Normal successful upload
    content1 = b"This is a test file."
    print(f"Test 1 (Normal): {upload_file('report.txt', content1)}")

    # Test Case 2: Uploading a file with the same name (should not overwrite)
    content2 = b"This is another test file."
    print(f"Test 2 (Duplicate Name): {upload_file('report.txt', content2)}")

    # Test Case 3: Path traversal attack attempt
    content3 = b"malicious content"
    print(f"Test 3 (Path Traversal): {upload_file('../../etc/passwd', content3)}")

    # Test Case 4: File size too large
    large_content = b'\0' * (MAX_FILE_SIZE + 1)
    print(f"Test 4 (Oversized File): {upload_file('large_file.zip', large_content)}")

    # Test Case 5: File with spaces and special characters in name
    content5 = b"Final document content."
    print(f"Test 5 (Special Chars): {upload_file('My Report (Final Version).docx', content5)}")
    
    print("---------------------------------")


if __name__ == "__main__":
    main()