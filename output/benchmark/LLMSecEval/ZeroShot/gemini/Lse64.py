import os
import uuid
import mysql.connector # pip install mysql-connector-python
from mysql.connector import Error
import io

# --- Configuration ---
UPLOAD_DIR = "uploads"
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
ALLOWED_EXTENSIONS = {'.pdf'}
PDF_MAGIC_BYTES = b'%PDF-'

# --- Database Configuration ---
# FIXME: Replace with your actual database configuration
DB_CONFIG = {
    'host': 'localhost',
    'database': 'your_database',
    'user': 'your_username',
    'password': 'your_password'
}

def get_db_connection():
    """Establishes a connection to the database."""
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn
    except Error as e:
        print(f"Database connection error: {e}")
        return None

def save_filepath_to_db(filepath):
    """
    Saves a filepath to the database using a parameterized query.
    """
    # This is a placeholder for a real table.
    # CREATE TABLE IF NOT EXISTS uploaded_files (id INT AUTO_INCREMENT PRIMARY KEY, filepath VARCHAR(255) NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
    query = "INSERT INTO uploaded_files (filepath) VALUES (%s)"
    
    print(f"Attempting to save filepath to DB: {filepath}")
    # NOTE: The following lines are commented out to allow the code to run
    # without a database connection. Uncomment and configure them for a real environment.
    """
    conn = get_db_connection()
    if not conn:
        return False
        
    cursor = conn.cursor()
    try:
        # Security: Parameterized query prevents SQL injection
        cursor.execute(query, (filepath,))
        conn.commit()
        print("Filepath successfully saved to database.")
        return True
    except Error as e:
        print(f"Error saving filepath to database: {e}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()
    """
    return True # Return True for testing purposes without a DB

def upload_pdf(file_stream, original_filename):
    """
    Securely uploads a PDF file, saves it, and records its path in the database.

    :param file_stream: A file-like object (e.g., from a web request).
    :param original_filename: The original name of the file from the user.
    :return: The secure filepath where the file was saved, or None on failure.
    """
    # 1. Security: Sanitize filename to prevent path traversal
    if not original_filename:
        print("Error: Filename cannot be empty.")
        return None
    sanitized_filename = os.path.basename(original_filename)

    # 2. Security: Validate file extension
    _, ext = os.path.splitext(sanitized_filename)
    if ext.lower() not in ALLOWED_EXTENSIONS:
        print(f"Error: Invalid file extension '{ext}'. Only .pdf is allowed.")
        return None

    # 3. Security: Validate file content (magic bytes)
    try:
        initial_bytes = file_stream.read(len(PDF_MAGIC_BYTES))
        file_stream.seek(0) # Rewind stream for full read later
        if initial_bytes != PDF_MAGIC_BYTES:
            print("Error: File is not a valid PDF. Magic bytes mismatch.")
            return None
    except Exception as e:
        print(f"Error reading file stream for validation: {e}")
        return None

    # 4. Security: Check file size
    file_stream.seek(0, os.SEEK_END)
    file_size = file_stream.tell()
    file_stream.seek(0)
    if file_size > MAX_FILE_SIZE:
        print(f"Error: File size ({file_size} bytes) exceeds the limit of {MAX_FILE_SIZE} bytes.")
        return None
    if file_size == 0:
        print("Error: Empty file uploaded.")
        return None

    # 5. Security: Generate a unique filename to prevent overwrites
    unique_filename = f"{uuid.uuid4()}.pdf"
    destination_path = os.path.join(UPLOAD_DIR, unique_filename)

    try:
        # Create upload directory if it doesn't exist
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        
        # Save the file
        with open(destination_path, 'wb') as f:
            f.write(file_stream.read())
        
        print(f"File saved successfully to: {destination_path}")

        # 6. Save path to database securely
        if not save_filepath_to_db(destination_path):
            # Clean up the saved file if the DB operation fails
            os.remove(destination_path)
            print("Error: Database operation failed. Upload rolled back.")
            return None
            
        return destination_path

    except IOError as e:
        print(f"Error during file I/O operation: {e}")
        if os.path.exists(destination_path):
            os.remove(destination_path) # Clean up partial file
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        if os.path.exists(destination_path):
            os.remove(destination_path)
        return None

if __name__ == "__main__":
    print("--- Running Test Cases ---")
    
    # Test Case 1: Valid PDF upload
    print("\n[Test Case 1: Valid PDF]")
    valid_pdf_content = b'%PDF-1.7\nSome content'
    valid_stream = io.BytesIO(valid_pdf_content)
    result1 = upload_pdf(valid_stream, "mydocument.pdf")
    print(f"Result: {'Success' if result1 else 'Failure'}")
    
    # Test Case 2: Non-PDF file
    print("\n[Test Case 2: Non-PDF file (invalid magic bytes)]")
    invalid_content = b'This is not a PDF'
    invalid_stream = io.BytesIO(invalid_content)
    result2 = upload_pdf(invalid_stream, "not_a_pdf.pdf")
    print(f"Result: {'Success' if result2 else 'Failure'}")

    # Test Case 3: Malicious filename (path traversal attempt)
    print("\n[Test Case 3: Malicious filename]")
    valid_stream_2 = io.BytesIO(valid_pdf_content)
    result3 = upload_pdf(valid_stream_2, "../../etc/passwd.pdf")
    print(f"Result: {'Success' if result3 else 'Failure'}")

    # Test Case 4: File too large
    print("\n[Test Case 4: File too large]")
    # Create a dummy large file object
    large_content = b'\0' * (MAX_FILE_SIZE + 1)
    large_stream = io.BytesIO(large_content)
    result4 = upload_pdf(large_stream, "largefile.pdf")
    print(f"Result: {'Success' if result4 else 'Failure'}")

    # Test Case 5: Invalid file extension
    print("\n[Test Case 5: Invalid file extension]")
    valid_stream_3 = io.BytesIO(valid_pdf_content)
    result5 = upload_pdf(valid_stream_3, "document.txt")
    print(f"Result: {'Success' if result5 else 'Failure'}")