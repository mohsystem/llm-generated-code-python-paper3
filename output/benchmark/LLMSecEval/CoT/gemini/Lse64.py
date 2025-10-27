import os
import uuid
import sys

UPLOAD_DIR = "uploads"
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
PDF_MAGIC_BYTES = b'%PDF-'

def upload_pdf(original_filename, file_content):
    """
    Simulates uploading a PDF file.
    
    :param original_filename: The original filename from the user.
    :param file_content: The byte content of the file.
    :return: The sanitized filepath where the file was saved, or None on failure.
    """
    if not all([original_filename, file_content]):
        print("Error: Invalid input provided.")
        return None

    # 1. Security: Check file size
    if sys.getsizeof(file_content) > MAX_FILE_SIZE:
        print(f"Error: File size exceeds the limit of {MAX_FILE_SIZE} bytes.")
        return None

    # 2. Security: Validate file type using magic bytes
    if not file_content.startswith(PDF_MAGIC_BYTES):
        print("Error: Invalid file type. Not a PDF.")
        return None
        
    # 3. Security: Prevent path traversal by extracting only the filename
    base_filename = os.path.basename(original_filename)

    # Ensure the filename ends with .pdf, but don't solely rely on it for security
    if not base_filename.lower().endswith('.pdf'):
        print("Error: Filename must end with .pdf.")
        return None

    # 4. Security: Generate a unique filename to prevent overwrites
    unique_filename = f"{uuid.uuid4()}.pdf"
    
    try:
        # Create the directory if it doesn't exist
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        
        destination_path = os.path.join(UPLOAD_DIR, unique_filename)
        
        # Save the file
        with open(destination_path, 'wb') as f:
            f.write(file_content)
        
        print(f"File saved successfully to: {destination_path}")
        
        # 5. Security: Simulate saving the filepath to a database using a prepared statement
        save_filepath_to_database(destination_path)
        
        return destination_path
        
    except IOError as e:
        print(f"File operation failed: {e}")
        return None

def save_filepath_to_database(file_path):
    """
    Simulates saving a filepath to a MySQL database using parameterized queries
    to prevent SQL Injection.
    """
    print("\n--- Simulating Database Interaction ---")
    # This is a placeholder for actual database logic
    # In a real application, you would use a library like mysql-connector-python
    # and use placeholders like %s
    sql = "INSERT INTO pdf_files (filepath) VALUES (%s);"
    print(f"SQL (Parameterized Query): {sql}")
    print(f"Binding parameter 1: {file_path}")
    print("Executing query...")
    print("Filepath successfully saved in the database.")
    print("-------------------------------------\n")

if __name__ == "__main__":
    print("--- Running Python Test Cases ---")

    # Test Case 1: Valid PDF upload
    print("--- Test Case 1: Valid PDF ---")
    valid_pdf_content = b"%PDF-1.5\n..."
    upload_pdf("document.pdf", valid_pdf_content)

    # Test Case 2: Invalid file type (not a PDF)
    print("--- Test Case 2: Invalid File Type (TXT) ---")
    invalid_content = b"This is a text file."
    upload_pdf("not_a_pdf.txt", invalid_content)

    # Test Case 3: Path traversal attempt
    print("--- Test Case 3: Path Traversal Attempt ---")
    upload_pdf("../../etc/passwd.pdf", valid_pdf_content)

    # Test Case 4: File too large
    print("--- Test Case 4: File Too Large ---")
    # Note: sys.getsizeof includes overhead. We create content that is clearly too large.
    large_content = bytearray(MAX_FILE_SIZE + 1)
    large_content[0:len(valid_pdf_content)] = valid_pdf_content
    upload_pdf("large_file.pdf", bytes(large_content))

    # Test Case 5: Another valid PDF to show unique naming
    print("--- Test Case 5: Another Valid PDF ---")
    upload_pdf("report.pdf", valid_pdf_content)