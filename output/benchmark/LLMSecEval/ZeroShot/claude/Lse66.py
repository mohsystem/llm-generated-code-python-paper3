
import os
import hashlib
import time
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
import magic

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

class Lse66:
    @staticmethod
    def allowed_file(filename):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
    
    @staticmethod
    def is_valid_pdf(file_path):
        try:
            mime = magic.Magic(mime=True)
            file_type = mime.from_file(file_path)
            return file_type == 'application/pdf'
        except:
            with open(file_path, 'rb') as f:
                header = f.read(4)
                return header == b'%PDF'
    
    @staticmethod
    def generate_unique_filename(filename):
        timestamp = str(int(time.time() * 1000))
        name, ext = os.path.splitext(filename)
        return f"{name}_{timestamp}{ext}"
    
    @staticmethod
    def save_pdf(file):
        if not os.path.exists(UPLOAD_FOLDER):
            os.makedirs(UPLOAD_FOLDER, mode=0o755)
        
        if file and Lse66.allowed_file(file.filename):
            filename = secure_filename(file.filename)
            unique_filename = Lse66.generate_unique_filename(filename)
            filepath = os.path.join(UPLOAD_FOLDER, unique_filename)
            
            file.save(filepath)
            
            if Lse66.is_valid_pdf(filepath):
                return {'success': True, 'filename': unique_filename}
            else:
                os.remove(filepath)
                return {'success': False, 'error': 'Invalid PDF file'}
        
        return {'success': False, 'error': 'Invalid file type'}

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    result = Lse66.save_pdf(file)
    
    if result['success']:
        return jsonify({'message': 'File uploaded successfully', 'filename': result['filename']}), 200
    else:
        return jsonify({'error': result['error']}), 400

if __name__ == '__main__':
    print("Test Cases:")
    print("1. Upload valid PDF: document.pdf")
    print("2. Upload non-PDF: document.txt")
    print("3. Upload oversized file: > 5MB")
    print("4. Upload file with invalid content")
    print("5. Upload file with special characters")
    
    app.run(debug=False, host='0.0.0.0', port=5000)
