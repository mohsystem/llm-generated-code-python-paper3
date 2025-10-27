import os
import shutil
import mysql.connector
from mysql.connector import Error

# --- DATABASE CONFIGURATION (Update with your details) ---
DB_CONFIG = {
    'host': 'localhost',
    'database': 'file_db',
    'user': 'your_username',
    'password': 'your_password'
}
UPLOAD_DIR = "uploads"

# Pre-requisites:
# 1. MySQL server is running.
# 2. A database named 'file_db' exists.
# 3. A table named 'files' exists in 'file_db'.
#    SQL to create table:
#    CREATE TABLE files (
#        id INT AUTO_INCREMENT PRIMARY KEY,
#        filepath VARCHAR(255) NOT NULL,
#        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
#    );
# 4. The mysql-connector-python library is installed.
#    Install using pip: pip install mysql-connector-python

def upload_pdf(source_file_path):
    """
    Simulates uploading a PDF by copying it to an 'uploads' folder
    and saving its new path to a MySQL database.

    :param source_file_path: The path to the local PDF file to be "uploaded".
    :return: True if successful, False otherwise.
    """
    if not os.path.exists(source_file_path) or not os.path.isfile(source_file_path):
        print(f"Error: Source file does not exist or is not a file: {source_file_path}")
        return False

    # Create the uploads directory if it doesn't exist
    try:
        os.makedirs(UPLOAD_DIR, exist_ok=True)
    except OSError as e:
        print(f"Error: Could not create upload directory '{UPLOAD_DIR}': {e}")
        return False

    file_name = os.path.basename(source_file_path)
    dest_path = os.path.join(UPLOAD_DIR, file_name)

    # 1. Save the file to the uploads folder
    try:
        shutil.copy(source_file_path, dest_path)
        print(f"File saved to: {dest_path}")
    except IOError as e:
        print(f"Error: Could not copy file: {e}")
        return False

    # 2. Save the filepath to the MySQL database
    conn = None
    cursor = None
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        if conn.is_connected():
            cursor = conn.cursor()
            sql_query = "INSERT INTO files (filepath) VALUES (%s)"
            # Normalize path for consistency (e.g., use forward slashes)
            db_filepath = dest_path.replace('\\', '/')
            cursor.execute(sql_query, (db_filepath,))
            conn.commit()
            if cursor.rowcount > 0:
                print("Filepath saved to database successfully.")
                return True
            else:
                print("Error: Failed to save filepath to database.")
                # Rollback file copy by deleting it
                os.remove(dest_path)
                return False

    except Error as e:
        print(f"Database Error: {e}")
        # Rollback file copy by deleting it
        if os.path.exists(dest_path):
            os.remove(dest_path)
        return False
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

def main():
    """ Main function with 5 test cases """
    # Create a directory for test files
    test_dir = "test_files"
    os.makedirs(test_dir, exist_ok=True)

    # Create 5 dummy files to act as PDFs
    test_files = [
        os.path.join(test_dir, "report-q1.pdf"),
        os.path.join(test_dir, "invoice-123.pdf"),
        os.path.join(test_dir, "manual_v2.pdf"),
        os.path.join(test_dir, "presentation.pdf"),
        os.path.join(test_dir, "non_existent_file.pdf")
    ]
    
    for i in range(4): # Create first 4 files
        with open(test_files[i], 'w') as f:
            f.write("dummy pdf content")

    print("--- Running 5 Test Cases ---")
    for i, file_path in enumerate(test_files):
        print(f"\n--- Test Case {i + 1}: Uploading {file_path} ---")
        result = upload_pdf(file_path)
        print(f"Result: {'SUCCESS' if result else 'FAILURE'}")

if __name__ == "__main__":
    main()