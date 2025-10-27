import os
import uuid
import tempfile
import shutil
import logging
from flask import Flask, request, redirect, url_for, flash, Response
from werkzeug.utils import secure_filename
import requests

# --- Configuration ---
UPLOAD_FOLDER = 'uploads'
# Whitelist of allowed file extensions
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
# Maximum file size allowed (10 MB)
MAX_FILE_SIZE = 10 * 1024 * 1024 

app = Flask(__name__)
# Configure a secret key for flashing messages
app.config['SECRET_KEY'] = os.urandom(24) 
# Configure the upload folder
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# Configure the maximum file size
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

# --- Helper Functions ---
def allowed_file(filename):
    """Check if the file has an allowed extension."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- Flask Routes ---
@app.route('/', methods=['GET'])
def index():
    """Render the upload form."""
    return '''
    <!doctype html>
    <title>Upload new File</title>
    <h1>Upload new File</h1>
    <form method=post action="/upload" enctype=multipart/form-data>
      <input type=file name=file>
      <input type=submit value=Upload>
    </form>
    '''

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file uploads."""
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    
    file = request.files['file']

    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('index'))

    # Use werkzeug's secure_filename to prevent path traversal and sanitize the name
    filename = secure_filename(file.filename)
    
    if file and allowed_file(filename):
        # Generate a unique filename to prevent overwrites and guessing
        file_ext = filename.rsplit('.', 1)[1].lower()
        unique_filename = f"{uuid.uuid4()}.{file_ext}"
        
        # Ensure the upload directory exists
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        temp_dir = app.config['UPLOAD_FOLDER']
        # Create a secure temporary file in the upload directory
        try:
            with tempfile.NamedTemporaryFile(dir=temp_dir, delete=False, mode='wb') as tmp:
                temp_path = tmp.name
                # Stream the file content to the temporary file
                file.save(tmp)
            
            # Atomically move the temporary file to its final destination
            final_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            shutil.move(temp_path, final_path)
            
            # Set restrictive file permissions (owner can read/write)
            os.chmod(final_path, 0o600)
            
            flash('File successfully uploaded')
            return Response(f"File uploaded successfully as {unique_filename}", status=200)
        except Exception as e:
            # Clean up temp file if it exists on error
            if 'temp_path' in locals() and os.path.exists(temp_path):
                os.remove(temp_path)
            logging.error(f"File upload failed: {e}")
            flash('An error occurred during file upload.')
            return Response("File upload failed.", status=500)

    else:
        flash('File type not allowed')
        return Response("File type not allowed.", status=400)


def run_tests():
    """Runs test cases against the local server."""
    base_url = "http://127.0.0.1:8080"
    upload_url = f"{base_url}/upload"
    
    print("\n--- Running Test Cases ---")
    
    test_cases = [
        {"name": "Valid .txt file", "filename": "test1.txt", "content": b"hello world", "expect_success": True},
        {"name": "Valid .jpg file", "filename": "test2.jpg", "content": b"\xff\xd8\xff\xe0", "expect_success": True},
        {"name": "Disallowed .html file", "filename": "test3.html", "content": b"<html></html>", "expect_success": False},
        {"name": "Path traversal attempt", "filename": "../../etc/passwd.txt", "content": b"root:x:0:0", "expect_success": True}, # secure_filename sanitizes this
        {"name": "No file part", "files": {}, "expect_success": False},
    ]

    for test in test_cases:
        print(f"[*] Running test: {test['name']}")
        try:
            if "files" in test: # Special case for no file part
                 r = requests.post(upload_url, files=test.get("files"))
            else:
                 files = {'file': (test['filename'], test['content'])}
                 r = requests.post(upload_url, files=files)
            
            is_success = 200 <= r.status_code < 300
            
            if is_success == test['expect_success']:
                print(f"[PASS] {test['name']} - Status: {r.status_code}")
            else:
                print(f"[FAIL] {test['name']} - Expected {'success' if test['expect_success'] else 'failure'}, but got status {r.status_code}. Response: {r.text}")

        except requests.exceptions.RequestException as e:
            print(f"[FAIL] {test['name']} - Request failed: {e}")

    print("--- Test Cases Finished ---")


if __name__ == '__main__':
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    
    # Check if we are in test mode or server mode
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == 'test':
        # To run tests, you need to run the server in a separate terminal
        # and then run 'python your_script_name.py test'
        run_tests()
    else:
        print("Starting server on http://127.0.0.1:8080")
        print("To run tests, run this script with the 'test' argument in another terminal.")
        app.run(host='127.0.0.1', port=8080, debug=False)