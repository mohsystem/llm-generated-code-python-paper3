import os
import uuid
from flask import Flask, request, redirect, url_for, flash

# In a real application, this should be configured securely.
# For this example, we create a folder in the current directory.
UPLOAD_FOLDER = 'webapp_uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Whitelist of allowed file extensions for security.
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# Secret key for flashing messages
app.secret_key = 'super secret key' 
# Security: Set a maximum file size (e.g., 10 MB) to prevent Denial of Service.
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024

def allowed_file(filename):
    """Checks if the file's extension is in the allowed list."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part in the request.')
            return redirect(request.url)
        
        file = request.files['file']
        
        # If the user does not select a file, the browser submits an empty file without a filename.
        if file.filename == '':
            flash('No selected file.')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            # Security: Get the original extension and generate a new, secure filename using UUID.
            # This prevents path traversal, directory traversal, and file overwrite attacks.
            extension = file.filename.rsplit('.', 1)[1].lower()
            secure_name = str(uuid.uuid4()) + '.' + extension
            
            # Save the file to the configured upload folder
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], secure_name))
            
            flash(f'File successfully uploaded and saved as {secure_name}')
            return redirect(url_for('upload_file'))
        else:
            flash(f'File type not allowed. Allowed types are: {", ".join(ALLOWED_EXTENSIONS)}')
            return redirect(request.url)

    # For GET requests, display the upload form.
    return '''
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-g">
        <title>Python File Upload</title>
    </head>
    <body>
        <h1>Upload a New File</h1>
        <!-- Display flashed messages -->
        {% with messages = get_flashed_messages() %}
          {% if messages %}
            <ul style="color:red;">
            {% for message in messages %}
              <li>{{ message }}</li>
            {% endfor %}
            </ul>
          {% endif %}
        {% endwith %}
        <form method=post enctype=multipart/form-data>
          <input type=file name=file>
          <input type=submit value=Upload>
        </form>
    </body>
    </html>
    '''

def Lse71():
    """Main function to run the Flask application."""
    print("Server starting on port 5000...")
    print("Access the application at http://127.0.0.1:5000")
    print(f"Uploaded files will be saved in the '{UPLOAD_FOLDER}' directory.")
    print("\n--- How to Test ---")
    print("1. Run this script: python your_script_name.py")
    print("2. Open http://127.0.0.1:5000 in your web browser.")
    print("3. Test Case 1 (Success): Upload a valid file like a .txt or .png file (less than 10MB).")
    print("4. Test Case 2 (Invalid Type): Try to upload a disallowed file like a .py or .html file.")
    print("5. Test Case 3 (No File): Click the 'Upload' button without selecting a file.")
    print("6. Test Case 4 (File Too Large): Try to upload a file larger than 10MB.")
    print("7. Test Case 5 (Path Traversal attempt): Rename a file to `../../evil.txt` and try to upload it. The server will safely handle it.")
    
    # In a production environment, use a proper WSGI server instead of app.run()
    app.run(host='0.0.0.0', port=5000)

if __name__ == '__main__':
    # This is the entry point for the application.
    Lse71()