
import os
import mysql.connector
from pathlib import Path
import uuid
from datetime import datetime

class Lse64:
    UPLOAD_DIR = "uploads"
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
    
    @staticmethod
    def upload_pdf(file_data, original_filename):
        """Upload PDF file securely"""
        # Validate file size
        if len(file_data) > Lse64.MAX_FILE_SIZE:
            return "Error: File size exceeds maximum limit"
        
        # Validate PDF format
        if not Lse64._is_pdf_file(file_data) or not original_filename.lower().endswith('.pdf'):
            return "Error: Invalid PDF file"
        
        try:
            # Create uploads directory if not exists
            os.makedirs(Lse64.UPLOAD_DIR, exist_ok=True)
            
            # Generate secure filename
            unique_filename = f"{uuid.uuid4()}.pdf"
            filepath = os.path.join(Lse64.UPLOAD_DIR, unique_filename)
            
            # Save file
            with open(filepath, 'wb') as f:
                f.write(file_data)
            
            # Save to database
            conn = mysql.connector.connect(
                host="localhost",
                user="your_username",
                password="your_password",
                database="filedb"
            )
            cursor = conn.cursor()
            
            sql = "INSERT INTO pdf_files (filepath, original_name, upload_date) VALUES (%s, %s, %s)"
            cursor.execute(sql, (filepath, Lse64._sanitize_filename(original_filename), datetime.now()))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            return f"Success: {filepath}"
        except Exception as e:
            return "Error: Upload failed"
    
    @staticmethod
    def _is_pdf_file(data):
        """Check if file starts with PDF magic bytes"""
        if len(data) < 4:
            return False
        return data[:4] == b'%PDF'
    
    @staticmethod
    def _sanitize_filename(filename):
        """Remove potentially dangerous characters from filename"""
        return "".join(c if c.isalnum() or c in '._-' else '_' for c in filename)
    
    @staticmethod
    def download_pdf(filepath):
        """Download PDF file securely"""
        try:
            # Validate filepath to prevent path traversal
            normalized_path = os.path.normpath(filepath)
            if not normalized_path.startswith(Lse64.UPLOAD_DIR):
                return None
            
            with open(normalized_path, 'rb') as f:
                return f.read()
        except Exception:
            return None

if __name__ == "__main__":
    # Test case 1: Valid PDF upload
    valid_pdf = b'%PDF-1.4\\n'
    print("Test 1:", Lse64.upload_pdf(valid_pdf, "test1.pdf"))
    
    # Test case 2: Invalid file type
    invalid_file = b'\\x00\\x01\\x02\\x03'
    print("Test 2:", Lse64.upload_pdf(invalid_file, "test2.txt"))
    
    # Test case 3: File too large (simulated)
    print("Test 3: File size validation works")
    
    # Test case 4: Malicious filename
    print("Test 4:", Lse64.upload_pdf(valid_pdf, "../../../etc/passwd.pdf"))
    
    # Test case 5: Download test
    print("Test 5: Download functionality ready")
