import os
from flask import Flask, request, redirect, url_for, flash
from werkzeug.utils import secure_filename
import uuid

# --- Security Configuration ---
# Define a secure, non-web-accessible directory for uploads.
UPLOAD_FOLDER = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'uploads')
# Whitelist of allowed file extensions.
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
# Maximum file size in bytes (e.g., 10 MB).
MAX_CONTENT_LENGTH = 10 * 1024 * 1024

app = Flask(__name__)
# It's important to set a secret key for flashing messages.
app.secret_key = 'super_secret_key' 
# Apply security configurations
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

def allowed_file(filename):
    """Checks if the file's extension is in the allowed whitelist."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/', methods=['GET'])
def index():
    """Serves the HTML upload form."""
    return '''
    <!doctype html>
    <title>Secure File Upload</title>
    <h1>Upload new File</h1>
    <form method=post action="/upload" enctype=multipart/form-data>
      <input type=file name=file>
      <input type=submit value=Upload>
    </form>
    '''

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handles the file upload logic."""
    # Check if the post request has the file part
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    
    file = request.files['file']

    # If the user does not select a file, the browser submits an empty file without a filename.
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('index'))

    if file and allowed_file(file.filename):
        # Security Check 1: Sanitize filename.
        # werkzeug.utils.secure_filename prevents directory traversal attacks.
        original_filename = secure_filename(file.filename)
        
        # Security Check 2: Generate a new, secure filename.
        # This prevents overwrites and hides internal file structure.
        extension = original_filename.rsplit('.', 1)[1].lower()
        new_filename = f"{uuid.uuid4()}.{extension}"
        
        # Save the file to the secure upload directory
        try:
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], new_filename))
            return f"File uploaded successfully as {new_filename}"
        except Exception as e:
            return f"An error occurred: {e}", 500
    else:
        return "File type not allowed.", 400


def main():
    """Main function to set up and run the web application."""
    # Create the upload directory if it doesn't exist
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    
    print("Server starting on http://127.0.0.1:5000")
    print(f"Upload directory: {os.path.abspath(UPLOAD_FOLDER)}")
    print("\n--- Test Cases (run in a separate terminal) ---")
    print("1. Valid TXT file upload:")
    print("   echo \"This is a test.\" > test.txt")
    print("   curl -F \"file=@test.txt\" http://127.0.0.1:5000/upload")
    print("\n2. Valid PNG file upload (create a dummy 1x1 png):")
    print("   curl -o test.png https://via.placeholder.com/1")
    print("   curl -F \"file=@test.png\" http://127.0.0.1:5000/upload")
    print("\n3. Invalid file type (e.g., .html):")
    print("   echo \"<html></html>\" > test.html")
    print("   curl -F \"file=@test.html\" http://127.0.0.1:5000/upload")
    print("\n4. File too large (create an ~11MB file):")
    print("   dd if=/dev/zero of=largefile.dat bs=1M count=11")
    print("   curl -F \"file=@largefile.dat\" http://127.0.0.1:5000/upload")
    print("\n5. Malicious filename (directory traversal attempt):")
    print("   echo \"malicious\" > ../../test.txt")
    print("   curl -F \"file=@../../test.txt\" http://127.0.0.1:5000/upload")
    
    app.run(debug=False) # debug=False is crucial for production security

if __name__ == '__main__':
    main()