import os
from flask import Flask, request, redirect, flash

# This code requires the Flask library.
# Install it using: pip install Flask

UPLOAD_FOLDER = 'uploads'

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = 'a_random_secret_key'

def upload_file():
    """The function that handles the file upload."""
    if 'file' not in request.files:
        flash('No file part')
        return "Error: No file part in request", 400
    
    file = request.files['file']
    
    if file.filename == '':
        flash('No selected file')
        return "Error: No file selected", 400
    
    if file:
        filename = file.filename
        # In a real app, you should secure the filename
        # from werkzeug.utils import secure_filename
        # filename = secure_filename(file.filename)
        
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return f'File "{filename}" uploaded successfully!'
    
    return "An unknown error occurred", 500

@app.route('/', methods=['GET'])
def index():
    return '''
    <!doctype html>
    <title>Python File Upload</title>
    <h1>Upload a File</h1>
    <form method=post action="/upload" enctype=multipart/form-data>
      <input type=file name=file>
      <input type=submit value=Upload>
    </form>
    '''

@app.route('/upload', methods=['POST'])
def upload_route():
    return upload_file()
    
# In Python, the main class name 'Lse70' is not idiomatic for a web app.
# The functionality is organized using functions and Flask's routing.
if __name__ == '__main__':
    # Create upload directory if it doesn't exist
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)

    print("Starting the Python Flask server on http://127.0.0.1:5000")
    print("Open your web browser to http://127.0.0.1:5000 to upload a file.")
    print("\n--- 5 Test Cases (using cURL) ---")
    print("NOTE: Ensure you have a file (e.g., test1.txt) in your current directory before running these commands.")
    print("1. Create a file for testing: echo 'hello python' > test1.txt")
    print("2. Test Case 1 (text file): curl -X POST -F 'file=@test1.txt' http://127.0.0.1:5000/upload")
    print("3. Create another file: echo 'print(\"hello\")' > test2.py")
    print("4. Test Case 2 (python file): curl -X POST -F 'file=@test2.py' http://127.0.0.1:5000/upload")
    print("5. Test Case 3 (POST with no file part): curl -X POST http://127.0.0.1:5000/upload")
    print("6. Test Case 4 (POST with empty file part): curl -X POST -F 'file=' http://127.0.0.1:5000/upload")
    print("7. Test Case 5 (POST with wrong field name): curl -X POST -F 'myFile=@test1.txt' http://127.0.0.1:5000/upload\n")
    
    app.run(host='0.0.0.0', port=5000)