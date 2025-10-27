import os
import re

# Define a secure location for uploads
UPLOAD_DIRECTORY = "uploads"
# Define a maximum file size to prevent Denial of Service (DoS) attacks (e.g., 10MB)
MAX_FILE_SIZE = 10 * 1024 * 1024

def save_pdf_file(original_filename, content):
    """
    Accepts a PDF file's name and content, validates it, and saves it to a
    predefined 'uploads' folder.
    
    :param original_filename: The original filename from the user.
    :param content: The file content as bytes.
    :return: A message indicating the result of the operation.
    """
    # 1. Security Check: File Size
    if len(content) > MAX_FILE_SIZE:
        return f"Error: File size exceeds the limit of {MAX_FILE_SIZE // (1024 * 1024)} MB."
    if not content:
        return "Error: File content cannot be empty."

    # 2. Security Check: Filename Validation and Sanitization
    if not original_filename:
        return "Error: Filename is missing."

    # Strip path information to prevent Path Traversal attacks (e.g., "../../etc/passwd")
    filename = os.path.basename(original_filename)

    # 3. Security Check: File Type
    # Ensure the file is a PDF by checking the extension.
    if not filename.lower().endswith(".pdf"):
        return "Error: Invalid file type. Only PDF files are allowed."

    # 4. Security Check: Sanitize filename characters
    # Remove any characters that are not alphanumeric, dots, underscores, or hyphens.
    sanitized_filename = re.sub(r'[^a-zA-Z0-9._-]', '', filename)
    
    if not sanitized_filename or sanitized_filename == ".pdf":
        return "Error: Invalid filename after sanitization."

    try:
        # Create the upload directory if it doesn't exist.
        # The 'exist_ok=True' argument prevents an error if the directory already exists.
        os.makedirs(UPLOAD_DIRECTORY, exist_ok=True)
        
        # Construct the final destination path securely.
        destination_path = os.path.join(UPLOAD_DIRECTORY, sanitized_filename)
        
        # Security check: ensure the resolved path is still within the upload directory
        if not os.path.abspath(destination_path).startswith(os.path.abspath(UPLOAD_DIRECTORY)):
             return "Error: Directory traversal attempt detected after path resolution."

        # Write the file in binary mode. 'with' statement ensures the file is closed.
        with open(destination_path, "wb") as f:
            f.write(content)
            
        return f"Success: File '{sanitized_filename}' saved successfully in '{UPLOAD_DIRECTORY}' folder."

    except IOError as e:
        # Log the exception properly in a real application
        print(f"I/O Error: {e}")
        return "Error: Could not save the file due to an I/O error."

if __name__ == "__main__":
    print("--- Running Python Test Cases ---")
    valid_content = b"This is a dummy PDF content."
    large_content = b'a' * (MAX_FILE_SIZE + 1)

    # Test Case 1: Valid PDF file
    print(f"Test 1 (Valid): {save_pdf_file('MyReport_2023.pdf', valid_content)}")
    
    # Test Case 2: Path Traversal attempt
    print(f"Test 2 (Path Traversal): {save_pdf_file('../../etc/passwd.pdf', valid_content)}")

    # Test Case 3: Invalid file type
    print(f"Test 3 (Invalid Type): {save_pdf_file('image.jpg', valid_content)}")

    # Test Case 4: Filename with malicious/invalid characters
    print(f"Test 4 (Invalid Chars): {save_pdf_file('a<b>c|d/e?f.pdf', valid_content)}")
    
    # Test Case 5: File too large
    print(f"Test 5 (Too Large): {save_pdf_file('large_document.pdf', large_content)}")
    print("---------------------------------\n")