import os
import re

# Define security constants
UPLOAD_DIR = "uploads"
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
PDF_MAGIC_BYTES = b'%PDF-'

def save_pdf(original_filename, file_content):
    """
    Securely saves a PDF file to the 'uploads' directory.
    
    :param original_filename: The original filename from the user.
    :param file_content: The byte content of the file.
    :return: True if the file was saved successfully, False otherwise.
    """
    # 1. Check for invalid inputs
    if not original_filename or not file_content:
        print("Error: Invalid filename or empty file content.")
        return False

    # 2. Security: Check file size
    if len(file_content) > MAX_FILE_SIZE:
        print(f"Error: File size exceeds the maximum limit of {MAX_FILE_SIZE} bytes.")
        return False

    # 3. Security: Validate file type by checking magic bytes
    if not file_content.startswith(PDF_MAGIC_BYTES):
        print("Error: File is not a valid PDF.")
        return False

    # 4. Security: Prevent path traversal by getting the base filename
    base_filename = os.path.basename(original_filename)

    # 5. Security: Sanitize the filename using a whitelist
    # Allow letters, numbers, underscore, hyphen, and period
    sanitized_filename = re.sub(r'[^a-zA-Z0-9_.-]', '_', base_filename)
    if not sanitized_filename.lower().endswith(".pdf"):
        sanitized_filename += ".pdf"

    try:
        # Ensure the upload directory exists
        os.makedirs(UPLOAD_DIR, exist_ok=True)

        # Construct the final, secure destination path
        # os.path.join is safe against path traversal when used with a sanitized basename
        destination_path = os.path.join(UPLOAD_DIR, sanitized_filename)

        # Write the file in binary mode
        with open(destination_path, "wb") as f:
            f.write(file_content)
        
        print(f"Successfully saved file to: {destination_path}")
        return True

    except IOError as e:
        print(f"Error saving file: {e}")
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return False

def main():
    print("--- Running Python Test Cases ---")

    # Test Case 1: Valid PDF file
    print("\n[Test 1] Valid PDF file")
    valid_pdf_content = b'%PDF-1.7... some pdf content...'
    save_pdf("my_document.pdf", valid_pdf_content)

    # Test Case 2: Path traversal attempt
    print("\n[Test 2] Path traversal attempt")
    save_pdf("../../etc/passwd.pdf", valid_pdf_content)

    # Test Case 3: Invalid file type (not a PDF)
    print("\n[Test 3] Invalid file type")
    non_pdf_content = b"<html>malicious script</html>"
    save_pdf("not_a_pdf.html", non_pdf_content)

    # Test Case 4: Filename with special characters
    print("\n[Test 4] Filename with special characters")
    save_pdf("file\"name/with:bad*chars.pdf", valid_pdf_content)
    
    # Test Case 5: File too large
    print("\n[Test 5] File too large")
    # Create a byte array larger than the max size
    large_content = PDF_MAGIC_BYTES + os.urandom(MAX_FILE_SIZE)
    save_pdf("very_large_document.pdf", large_content)

    print("\n--- Python Test Cases Finished ---")

if __name__ == "__main__":
    main()