
import os
import mysql.connector
from mysql.connector import Error
import uuid
from datetime import datetime
import shutil

UPLOAD_DIR = "uploads/"
DB_CONFIG = {
    'host': 'localhost',
    'database': 'pdfdb',
    'user': 'root',
    'password': 'password'
}

def upload_pdf(file_content, original_filename):
    """Upload PDF file and save filepath to database"""
    # Validate file extension
    if not original_filename.lower().endswith('.pdf'):
        return "Error: Only PDF files are allowed"
    
    # Create uploads directory if it doesn't exist\n    os.makedirs(UPLOAD_DIR, exist_ok=True)\n    \n    # Generate unique filename\n    unique_filename = str(uuid.uuid4()) + "_" + original_filename\n    filepath = os.path.join(UPLOAD_DIR, unique_filename)\n    \n    try:\n        # Save file to uploads folder\n        with open(filepath, 'wb') as f:\n            f.write(file_content)\n        \n        # Save filepath to database\n        save_filepath_to_database(filepath, original_filename)\n        \n        return f"Success: {filepath}"\n    except Exception as e:\n        return f"Error: {str(e)}"\n\ndef save_filepath_to_database(filepath, original_filename):\n    """Save filepath to MySQL database"""\n    try:\n        connection = mysql.connector.connect(**DB_CONFIG)\n        cursor = connection.cursor()\n        \n        sql = "INSERT INTO pdf_files (filepath, original_name, upload_date) VALUES (%s, %s, %s)"\n        values = (filepath, original_filename, datetime.now())\n        \n        cursor.execute(sql, values)\n        connection.commit()\n        \n        cursor.close()\n        connection.close()\n    except Error as e:\n        raise Exception(f"Database error: {e}")\n\ndef download_pdf(filepath):\n    """Download PDF file from filepath"""\n    # Validate filepath to prevent directory traversal\n    if ".." in filepath or not filepath.startswith(UPLOAD_DIR):\n        return None\n    \n    try:\n        with open(filepath, 'rb') as f:\n            return f.read()\n    except Exception as e:\n        print(f"Error downloading file: {e}")\n        return None\n\ndef main():\n    """Test cases"""\n    # Test case 1: Valid PDF upload\n    try:\n        test_content1 = b"PDF content test 1"\n        result1 = upload_pdf(test_content1, "test1.pdf")\n        print(f"Test 1: {result1}")\n    except Exception as e:\n        print(f"Test 1 failed: {e}")\n    \n    # Test case 2: Valid PDF upload\n    try:\n        test_content2 = b"PDF content test 2"\n        result2 = upload_pdf(test_content2, "document.pdf")\n        print(f"Test 2: {result2}")\n    except Exception as e:\n        print(f"Test 2 failed: {e}")\n    \n    # Test case 3: Invalid file extension\n    try:\n        test_content3 = b"Not a PDF"\n        result3 = upload_pdf(test_content3, "malicious.exe")\n        print(f"Test 3: {result3}")\n    except Exception as e:\n        print(f"Test 3 failed: {e}")\n    \n    # Test case 4: Download valid file\n    print("Test 4: Attempting to download uploads/test.pdf")\n    download_result = download_pdf("uploads/test.pdf")\n    print(f"Test 4: {'Success' if download_result else 'Failed'}")\n    \n    # Test case 5: Directory traversal attempt\n    print("Test 5: Attempting directory traversal")\n    traversal_result = download_pdf("../../../etc/passwd")\n    print(f"Test 5: {'Blocked (Success)' if traversal_result is None else 'Failed'}")\n\nif __name__ == "__main__":
    main()
