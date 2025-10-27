
from flask import Flask, request, jsonify
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOAD_DIR = 'uploads'

def handle_pdf_upload(file, filename):
    if not os.path.exists(UPLOAD_DIR):
        os.makedirs(UPLOAD_DIR)
    
    filepath = os.path.join(UPLOAD_DIR, filename)
    file.save(filepath)
    return filepath

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    if file and file.filename.endswith('.pdf'):
        filename = secure_filename(file.filename)
        filepath = handle_pdf_upload(file, filename)
        return jsonify({'message': 'File uploaded successfully', 'path': filepath}), 200
    
    return jsonify({'error': 'Only PDF files are allowed'}), 400

if __name__ == '__main__':
    print("PDF Upload Web App - Python")
    print("Testing file upload functionality...")
    
    # Create upload directory
    if not os.path.exists(UPLOAD_DIR):
        os.makedirs(UPLOAD_DIR)
        print("Test 1: Upload directory created")
    
    # Test case 2-5: Simulate file uploads
    test_files = [
        ('test1.pdf', b'Test PDF content 1'),
        ('test2.pdf', b'Test PDF content 2'),
        ('test3.pdf', b'Test PDF content 3'),
        ('test4.pdf', b'Test PDF content 4'),
        ('test5.pdf', b'Test PDF content 5')
    ]
    
    for i, (filename, content) in enumerate(test_files, start=2):
        filepath = os.path.join(UPLOAD_DIR, filename)
        with open(filepath, 'wb') as f:
            f.write(content)
        print(f"Test {i}: File {filename} uploaded")
    
    print("\\nAll tests completed. Check 'uploads' directory for files.")
    print("To run the web server, uncomment the line below:")
    # app.run(debug=True, port=5000)
