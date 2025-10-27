
from flask import Flask, request
import os

app = Flask(__name__)
UPLOAD_DIR = 'uploads'

def upload_file():
    if not os.path.exists(UPLOAD_DIR):
        os.makedirs(UPLOAD_DIR)
    
    if 'file' not in request.files:
        return 'No file part', 400
    
    file = request.files['file']
    
    if file.filename == '':
        return 'No selected file', 400
    
    if file:
        filepath = os.path.join(UPLOAD_DIR, file.filename)
        file.save(filepath)
        return f'File uploaded successfully: {file.filename}', 200

@app.route('/upload', methods=['POST'])
def upload():
    return upload_file()

if __name__ == '__main__':
    # Create test files for demonstration
    test_dir = 'test_files'
    if not os.path.exists(test_dir):
        os.makedirs(test_dir)
    
    # Create 5 test files
    for i in range(1, 6):
        test_file = os.path.join(test_dir, f'test_file_{i}.txt')
        with open(test_file, 'w') as f:
            f.write(f'This is test file {i} content.')
    
    print("Starting file upload server on port 5000...")
    print(f"Upload directory: {UPLOAD_DIR}")
    print("Send POST requests to http://localhost:5000/upload")
    print(f"\\nTest files created in '{test_dir}' directory")
    print("You can test with curl:")
    for i in range(1, 6):
        print(f"curl -X POST -F 'file=@test_files/test_file_{i}.txt' http://localhost:5000/upload")
    
    app.run(debug=True, port=5000)
