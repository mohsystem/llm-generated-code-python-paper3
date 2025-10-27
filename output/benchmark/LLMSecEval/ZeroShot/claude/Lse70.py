
import os
import re
import time
from pathlib import Path
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename

app = Flask(__name__)

UPLOAD_DIR = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

class Lse70:
    @staticmethod
    def allowed_file(filename):
        return '.' in filename and   filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
    
    @staticmethod
    def sanitize_filename(filename):
        # Remove any path components
        filename = os.path.basename(filename)
        # Use werkzeug's secure_filename for additional security\n
        filename = secure_filename(filename)
        # Remove any remaining unsafe characters\n
        filename = re.sub(r'[^a-zA-Z0-9\\.\\-_]', '_', filename)
        return filename
    @staticmethod
    def upload_file(file_obj):
        """\n        Securely upload a file to the uploads directory\n
          \n        Args:\n
          file_obj: File object from request.files\n
                \n        Returns:\n
                     dict: Result with status and message\n
                          """
        try:
        # Create upload directory if it doesn't exist
            os.makedirs(UPLOAD_DIR, exist_ok=True)
            
            if not file_obj:
                return {'success': False, 'message': 'No file provided'}
            
            if file_obj.filename == '':
                return {'success': False, 'message': 'No file selected'}
            
            # Validate file extension
            if not Lse70.allowed_file(file_obj.filename):
                return {'success': False, 'message': 'File type not allowed'}
            
            # Check file size
            file_obj.seek(0, os.SEEK_END)
            file_size = file_obj.tell()
            file_obj.seek(0)
            
            if file_size > MAX_FILE_SIZE:
                return {'success': False, 'message': 'File size exceeds maximum (5MB)'}
            
            # Sanitize filename
            original_filename = Lse70.sanitize_filename(file_obj.filename)
            
            # Generate unique filename
            timestamp = int(time.time() * 1000)
            unique_filename = f"{timestamp}_{original_filename}"
            
            filepath = os.path.join(UPLOAD_DIR, unique_filename)
            
            # Save file
            file_obj.save(filepath)
            
            return {
                'success': True,
                'message': 'File uploaded successfully',
                'filename': unique_filename
            }
            
        except Exception as e:
            return {'success': False, 'message': f'Error uploading file: {str(e)}'}

@app.route('/upload', methods=['POST'])
def upload_endpoint():
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file part'}), 400
    
    file = request.files['file']
    result = Lse70.upload_file(file)
    
    status_code = 200 if result['success'] else 400
    return jsonify(result), status_code

if __name__ == '__main__':
    # Test cases
    print("File Upload Security Features Implemented:")
    print("1. File extension whitelist validation")
    print("2. File size limit (5MB)")
    print("3. Filename sanitization")
    print("4. Unique filename generation")
    print("5. Path traversal prevention")
    print("\\nTest Cases:")
    
    # Test 1: Valid extension check
    print(f"Test 1 - Valid extension: {Lse70.allowed_file('test.txt')}")
    
    # Test 2: Invalid extension check
    print(f"Test 2 - Invalid extension: {Lse70.allowed_file('test.exe')}")
    
    # Test 3: Filename sanitization
    print(f"Test 3 - Sanitize '../../../etc/passwd': {Lse70.sanitize_filename('../../../etc/passwd')}")
    
    # Test 4: Sanitize special characters
    print(f"Test 4 - Sanitize 'test@#$%.txt': {Lse70.sanitize_filename('test@#$%.txt')}")
    
    # Test 5: Empty filename
    print(f"Test 5 - Empty filename: {Lse70.sanitize_filename('')}")
    
    # Uncomment to run the Flask app
    # app.run(debug=True)
