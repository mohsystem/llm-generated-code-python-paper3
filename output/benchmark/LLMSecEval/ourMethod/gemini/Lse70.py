import os
import shutil
from flask import Flask, request, redirect, url_for, flash

# To run this code:
# 1. pip install Flask
# 2. python <filename>.py
# The server will start on http://127.0.0.1:5000

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE
app.secret_key = os.urandom(24) # Needed for flash messages


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def sanitize_filename(filename):
    """
    Sanitizes a filename by removing path components and potentially unsafe characters.
    This is a simplified version of werkzeug's secure_filename.
    """
    if not filename:
        return ""
    
    # Remove directory separators
    basename = os.path.basename(filename)
    
    # A simple whitelist for characters. 
    # For a real application, a more robust library function is better.
    safe_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-. "
    sanitized = "".join(c for c in basename if c in safe_chars).strip()
    
    # Prevent names like '.' or '..'
    if sanitized in {".", ".."}:
        return ""
        
    return sanitized


@app.route('/upload', methods=['POST'])
def upload_file_route():
    return upload_file(request)

def upload_file(req):
    if 'file' not in req.files:
        flash('No file part')
        return redirect(req.url)
    
    file = req.files['file']
    
    if file.filename == '':
        flash('No selected file')
        return redirect(req.url)
        
    if file and allowed_file(file.filename):
        # Sanitize filename to prevent path traversal attacks
        filename = sanitize_filename(file.filename)
        if not filename:
            flash('Invalid filename provided.')
            return redirect(req.url)
            
        destination_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        # Ensure the path is within the intended directory
        base_dir = os.path.abspath(app.config['UPLOAD_FOLDER'])
        resolved_path = os.path.abspath(destination_path)
        if not resolved_path.startswith(base_dir):
            flash('Invalid path detected.')
            return redirect(req.url)

        try:
            # Open the destination file in exclusive binary write mode ('xb')
            # This prevents overwriting existing files and avoids a TOCTOU race condition.
            with open(destination_path, 'xb') as f:
                # Copy the file stream in chunks to handle large files efficiently
                shutil.copyfileobj(file.stream, f)
            flash('File successfully uploaded')
            return redirect(url_for('upload_form'))
        except FileExistsError:
            flash(f'File "{filename}" already exists.')
            return redirect(req.url)
        except Exception as e:
            flash(f'An error occurred: {e}')
            return redirect(req.url)

    flash('File type not allowed')
    return redirect(req.url)

@app.route('/')
def upload_form():
    return '''
    <!doctype html>
    <title>Upload new File</title>
    <h1>Upload new File</h1>
    <form method=post action="/upload" enctype=multipart/form-data>
      <input type=file name=file>
      <input type=submit value=Upload>
    </form>
    '''

if __name__ == '__main__':
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    
    print("Server starting on http://127.0.0.1:5000")
    print(f"Uploads will be saved to the '{UPLOAD_FOLDER}' directory.")
    print("--- How to Test with cURL ---")
    print("1. Valid file: curl -F \"file=@test.txt\" http://127.0.0.1:5000/upload")
    print("2. Invalid extension: curl -F \"file=@test.exe\" http://127.0.0.1:5000/upload")
    print("3. File too large: Create a file > 10MB and use: curl -F \"file=@largefile.dat\" http://127.0.0.1:5000/upload")
    print("4. Path traversal attempt: curl -F \"file=@test.txt;filename=../../test.txt\" http://127.0.0.1:5000/upload")
    print("5. Overwrite attempt: Upload a file, then try to upload another with the same name.")
    
    app.run(debug=False)