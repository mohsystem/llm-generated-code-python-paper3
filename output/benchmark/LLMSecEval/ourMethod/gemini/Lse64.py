import os
import uuid
import mysql.connector
import logging

# --- Configuration ---
# WARNING: Do not hardcode credentials in production. Use a secure method
# like environment variables or a secrets management system.
DB_CONFIG = {
    'host': 'localhost',
    'user': 'user',
    'password': 'password',
    'database': 'filedb'
}

UPLOADS_DIR = "uploads"
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def upload_pdf(original_filename: str, file_content: bytes) -> str | None:
    """
    Saves an uploaded PDF file to a secure directory and records its path in the database.

    :param original_filename: The original filename from the user.
    :param file_content: The byte content of the file.
    :return: The new, securely generated filename, or None on failure.
    """
    # Rule #1: Validate input
    if not original_filename or not original_filename.lower().endswith('.pdf'):
        logging.warning("Invalid file upload attempt: not a PDF or empty filename.")
        return None

    if not file_content or len(file_content) > MAX_FILE_SIZE:
        logging.warning("Invalid file upload attempt: File is empty or exceeds max size.")
        return None

    # Rule #5: Prevent path traversal by generating a new, safe filename.
    safe_filename = f"{uuid.uuid4()}.pdf"
    
    try:
        # Get the canonical path of the intended upload directory
        base_dir = os.path.realpath(UPLOADS_DIR)
        os.makedirs(base_dir, exist_ok=True)
        
        file_path = os.path.join(base_dir, safe_filename)
        
        # Final security check to ensure the path hasn't been manipulated.
        if os.path.realpath(file_path) != file_path:
             logging.error("Path validation failed. Aborting.")
             return None
        if not os.path.realpath(file_path).startswith(base_dir):
            logging.error(f"Security Alert: Path traversal attempt detected and blocked for path {file_path}")
            return None
    except Exception as e:
        logging.error(f"Error resolving file path: {e}")
        return None

    # Rule #6: Use exclusive creation mode 'xb' to prevent TOCTOU race conditions.
    try:
        with open(file_path, 'xb') as f:
            f.write(file_content)
    except FileExistsError:
        logging.error(f"File with generated name {safe_filename} already exists. This is highly unlikely.")
        return None
    except IOError as e:
        logging.error(f"Failed to write file: {e}")
        return None

    # Save the relative path to the database
    db_path = os.path.join(UPLOADS_DIR, safe_filename)
    conn = None
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        # Use prepared statements to prevent SQL injection
        sql = "INSERT INTO files (filepath) VALUES (%s)"
        cursor.execute(sql, (db_path,))
        conn.commit()
        
        logging.info(f"Successfully uploaded {safe_filename} and saved path to DB.")
        return safe_filename
    except mysql.connector.Error as e:
        logging.error(f"Database error: {e}")
        # Clean up the created file if DB insertion fails
        if os.path.exists(file_path):
            os.remove(file_path)
        return None
    finally:
        if conn and conn.is_connected():
            conn.close()


def download_pdf(filename: str) -> bytes | None:
    """
    Downloads a file by retrieving its path from the database.

    :param filename: The secure filename used to store the file.
    :return: The byte content of the file, or None if not found or an error occurs.
    """
    # Rule #1: Validate input
    if not filename or '/' in filename or '\\' in filename:
        logging.warning("Invalid filename for download.")
        return None

    file_path_from_db = None
    conn = None
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        sql = "SELECT filepath FROM files WHERE filepath LIKE %s"
        # Search for a path ending with the safe filename
        path_suffix = f"%{os.path.sep}{filename}"
        cursor.execute(sql, (path_suffix,))
        
        result = cursor.fetchone()
        if result:
            file_path_from_db = result[0]
        else:
            logging.warning(f"File not found in database: {filename}")
            return None
    except mysql.connector.Error as e:
        logging.error(f"Database error during file path retrieval: {e}")
        return None
    finally:
        if conn and conn.is_connected():
            conn.close()

    # Rule #5: Validate the path retrieved from the database
    try:
        base_dir = os.path.realpath(UPLOADS_DIR)
        full_path = os.path.realpath(file_path_from_db)

        # This check is crucial to prevent downloading files from outside the uploads directory.
        if not full_path.startswith(base_dir):
            logging.error(f"Security Alert: Attempt to access file outside of uploads directory: {full_path}")
            return None
        
        if not os.path.isfile(full_path):
             logging.error("Security Alert: Path does not point to a regular file.")
             return None

        with open(full_path, 'rb') as f:
            return f.read()
    except (IOError, TypeError) as e:
        logging.error(f"Could not read file for download: {e}")
        return None

def setup_test_environment():
    """Create upload dir and database table for testing."""
    os.makedirs(UPLOADS_DIR, exist_ok=True)
    conn = None
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id INT AUTO_INCREMENT PRIMARY KEY,
                filepath VARCHAR(255) NOT NULL UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("TRUNCATE TABLE files")
        conn.commit()
        logging.info("Database table 'files' is ready for testing.")
    except mysql.connector.Error as e:
        logging.error(f"Could not connect to database or create table: {e}")
        logging.error("Tests will likely fail. Please check credentials and ensure MySQL is running.")
    finally:
        if conn and conn.is_connected():
            conn.close()

if __name__ == "__main__":
    setup_test_environment()
    
    print("--- Running 5 Test Cases ---")

    # Test Case 1: Successful upload of a valid PDF
    print("\n[Test 1] Uploading a valid PDF file...")
    pdf_content = b"This is a fake PDF."
    saved_filename = upload_pdf("mydocument.pdf", pdf_content)
    if saved_filename:
        print(f"Success! File saved as: {saved_filename}")
    else:
        print("Failure. File not uploaded.")

    # Test Case 2: Attempt to upload a non-PDF file
    print("\n[Test 2] Attempting to upload a .txt file...")
    result2 = upload_pdf("not_a_pdf.txt", b"some text")
    if result2 is None:
        print("Success! Upload was correctly rejected.")
    else:
        print("Failure. A non-PDF file was accepted.")

    # Test Case 3: Attempt path traversal in filename
    print("\n[Test 3] Attempting path traversal: ../../evil.pdf...")
    result3 = upload_pdf("../../evil.pdf", b"evil content")
    if result3:
        print(f"Success! Upload succeeded but path traversal was prevented. Safe name: {result3}")
    else:
        print("Failure. Upload failed for an unexpected reason.")

    # Test Case 4: Attempt to upload a file that is too large
    print("\n[Test 4] Attempting to upload a file larger than MAX_FILE_SIZE...")
    large_content = b'a' * (MAX_FILE_SIZE + 1)
    result4 = upload_pdf("largefile.pdf", large_content)
    if result4 is None:
        print("Success! Large file was correctly rejected.")
    else:
        print("Failure. A large file was accepted.")

    # Test Case 5: Successful download of the first uploaded file
    print("\n[Test 5] Attempting to download the first valid file...")
    if saved_filename:
        downloaded_content = download_pdf(saved_filename)
        if downloaded_content and downloaded_content == pdf_content:
            print("Success! Downloaded content matches uploaded content.")
        else:
            print("Failure. Download failed or content mismatch.")
    else:
        print("Skipping test, as the initial upload failed.")