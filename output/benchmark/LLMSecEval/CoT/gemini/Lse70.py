import os
from flask import Flask, request, redirect, url_for, flash
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16 MB

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE
app.secret_key = 'super secret key' # Needed for flash messages

def allowed_file(filename):
    """Checks if the file extension is allowed."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/', methods=['GET'])
def index():
    """Serves the upload form."""
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
    """Handles the file upload."""
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    
    file = request.files['file']

    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('index'))

    if file and allowed_file(file.filename):
        # Security: Sanitize the filename to prevent path traversal attacks.
        # e.g., "../../etc/passwd" becomes "etc_passwd"
        filename = secure_filename(file.filename)
        
        # Ensure the upload directory exists
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Security: Check if file already exists to prevent overwrites,
        # though a better strategy is to generate a unique filename.
        if os.path.exists(save_path):
            flash(f'File {filename} already exists.')
            return redirect(url_for('index'))
            
        file.save(save_path)
        flash(f'File {filename} uploaded successfully')
        return redirect(url_for('index'))
    else:
        flash('File type not allowed')
        return redirect(url_for('index'))

# Main function with test case instructions
def main():
    print("--- To run the server, execute: flask --app <filename> run ---")
    print("--- Or uncomment the app.run() line below and run 'python <filename>.py' ---")
    print("\n--- Test Cases (use curl from a separate terminal) ---")
    print("1. Valid PNG upload: \n   (create a file 'test.png')\n   curl -X POST -F 'file=@test.png' http://127.0.0.1:5000/upload")
    print("2. Invalid file type (e.g., .html): \n   (create a file 'test.html')\n   curl -X POST -F 'file=@test.html' http://127.0.0.1:5000/upload")
    print("3. Malicious filename (path traversal): \n   (create a file 'test.txt')\n   curl -X POST -F 'file=@test.txt;filename=../../malicious.txt' http://127.0.0.1:5000/upload")
    print("4. No file uploaded: \n   curl -X POST http://127.0.0.1:5000/upload")
    print("5. Large file (Flask will return 413 Payload Too Large if file > 16MB)")
    # To run the server directly from the script:
    # app.run(debug=True)

if __name__ == '__main__':
    main()