# To run this code:
# 1. Install Flask: pip install Flask
# 2. Run the script: python your_script_name.py
# 3. The server will start on http://127.0.0.1:5000
# 4. Use a tool like curl or a web browser to send POST requests to http://127.0.0.1:5000/upload

import os
from flask import Flask, request, make_response
from werkzeug.utils import secure_filename
import uuid

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
# Max file size: 10 MB
MAX_FILE_SIZE = 10 * 1024 * 1024

app = Flask(__name__)
# It's important to set a secret key in a real app, e.g., for flashing messages
app.secret_key = os.urandom(24)

def allowed_file(filename):
    """Checks if the file's extension is in the allowed set."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handles the file upload."""
    if 'file' not in request.files:
        return make_response("No file part in the request", 400)
    
    file = request.files['file']

    if file.filename == '':
        return make_response("No selected file", 400)

    # Check file size by seeking to the end. This is simple but loads the file into memory.
    # For very large files, checking request.content_length is more memory-efficient.
    file.seek(0, os.SEEK_END)
    file_length = file.tell()
    if file_length > MAX_FILE_SIZE:
        return make_response(f"File is too large. Maximum size is {MAX_FILE_SIZE / 1024 / 1024} MB", 413)
    file.seek(0) # Reset file pointer

    # Sanitize filename provided by the user and validate extension
    original_filename = secure_filename(file.filename)
    if file and allowed_file(original_filename):
        # Generate a new secure filename using UUID to avoid name conflicts
        extension = original_filename.rsplit('.', 1)[1].lower()
        new_filename = f"{uuid.uuid4()}.{extension}"
        
        if not os.path.exists(UPLOAD_FOLDER):
            os.makedirs(UPLOAD_FOLDER)
            
        file.save(os.path.join(UPLOAD_FOLDER, new_filename))
        return make_response(f"File uploaded successfully as {new_filename}", 200)
    else:
        return make_response(f"File type not allowed. Allowed types are: {list(ALLOWED_EXTENSIONS)}", 400)

@app.route('/', methods=['GET'])
def index():
    """Provides a simple upload form for browser testing."""
    return '''
    <!doctype html>
    <title>Upload new File</title>
    <h1>Upload new File</h1>
    <form method=post action="/upload" enctype=multipart/form-data>
      <input type=file name=file>
      <input type=submit value=Upload>
    </form>
    '''

def Lse70():
    """Main function to run the application."""
    print("Starting Flask server on http://127.0.0.1:5000")
    print("Use a browser to access the root URL or use the curl commands below for testing.")
    print("\n--- 5 Test Cases (using curl) ---")

    print("\n1. Test Case: Successful upload of an allowed file type (.txt)")
    print("echo \"This is a test file.\" > test.txt")
    print("curl -X POST -F 'file=@test.txt' http://127.0.0.1:5000/upload")

    print("\n2. Test Case: Attempted upload of a disallowed file type (.exe)")
    print("echo \"dummy exe\" > test.exe")
    print("curl -X POST -F 'file=@test.exe' http://127.0.0.1:5000/upload")

    print("\n3. Test Case: Attempted upload of a file that is too large (e.g., > 10MB)")
    print("fallocate -l 11M largefile.dat")
    print("curl -X POST -F 'file=@largefile.dat' http://127.0.0.1:5000/upload")

    print("\n4. Test Case: Attempted upload with a malicious filename (path traversal)")
    print("echo \"malicious content\" > evil.txt")
    print("curl -X POST -F 'file=@evil.txt;filename=\"../../evil.txt\"' http://127.0.0.1:5000/upload")

    print("\n5. Test Case: Successful upload of another allowed file type (.jpg)")
    print("# (Assuming you have a file named 'image.jpg' in the current directory)")
    print("curl -X POST -F 'file=@image.jpg' http://127.0.0.1:5000/upload\n")
    
    app.run(debug=False)

if __name__ == '__main__':
    Lse70()