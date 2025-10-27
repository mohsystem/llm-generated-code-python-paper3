import os
import mysql.connector
from datetime import datetime
import shutil

UPLOAD_DIR = "uploads/"
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'password',
    'database': 'pdf_db'
}


def upload_pdf(source_file_path, file_name):
    """Upload PDF function"""
    try:
        # Create uploads directory if it doesn't exist
        if not os.path.exists(UPLOAD_DIR):
            os.makedirs(UPLOAD_DIR)

        # Generate unique filename
        unique_filename = f"{int(datetime.now().timestamp() * 1000)}_{file_name}"
        destination_path = os.path.join(UPLOAD_DIR, unique_filename)

        # Copy file to uploads folder
        shutil.copy2(source_file_path, destination_path)

        # Save filepath to database
        save_to_database(destination_path, file_name)

        return destination_path
    except Exception as e:
        print(f"Error uploading PDF: {e}")
        return None


def save_to_database(filepath, filename):
    """Save filepath to database"""
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()

        sql = "INSERT INTO pdf_files (filepath, filename, upload_date) VALUES (%s, %s, NOW())"
        cursor.execute(sql, (filepath, filename))

        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Error saving to database: {e}")


def download_pdf(file_id, download_path):
    """Download PDF function"""
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()

        sql = "SELECT filepath FROM pdf_files WHERE id = %s"
        cursor.execute(sql, (file_id,))
        result = cursor.fetchone()

        if result:
            filepath = result[0]
            shutil.copy2(filepath, download_path)
            cursor.close()
            conn.close()
            return True

        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Error downloading PDF: {e}")

    return False


if __name__ == "__main__":
    print("PDF Upload/Download System Test Cases:")

    # Test Case 1: Upload a PDF file
    print("\nTest Case 1: Upload PDF")
    result1 = upload_pdf("test1.pdf", "document1.pdf")
    print(f"Upload result: {'Success - ' + result1 if result1 else 'Failed'}")

    # Test Case 2: Upload another PDF file
    print("\nTest Case 2: Upload another PDF")
    result2 = upload_pdf("test2.pdf", "document2.pdf")
    print(f"Upload result: {'Success - ' + result2 if result2 else 'Failed'}")

    # Test Case 3: Upload PDF with special characters
    print("\nTest Case 3: Upload PDF with special name")
    result3 = upload_pdf("test3.pdf", "my_document_2024.pdf")
    print(f"Upload result: {'Success - ' + result3 if result3 else 'Failed'}")

    # Test Case 4: Download PDF by ID
    print("\nTest Case 4: Download PDF")
    download1 = download_pdf(1, "downloaded_file1.pdf")
    print(f"Download result: {'Success' if download1 else 'Failed'}")

    # Test Case 5: Download non-existent PDF
    print("\nTest Case 5: Download non-existent PDF")
    download2 = download_pdf(9999, "downloaded_file2.pdf")
    print(f"Download result: {'Success' if download2 else 'Failed (Expected)'}")
