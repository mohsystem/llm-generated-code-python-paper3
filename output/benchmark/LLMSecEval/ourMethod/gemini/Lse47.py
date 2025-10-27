import os
from flask import Flask, send_from_directory, abort
from werkzeug.utils import secure_filename
import sys

# Define the base directory for images relative to the script's location
# Using os.path.abspath ensures we have a canonical path to compare against
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
IMAGE_DIR = os.path.join(BASE_DIR, 'images')

app = Flask(__name__)

# A decorator used to tell what URL should trigger our function.
@app.route('/images/<path:filename>')
def serve_image(filename):
    """
    This function checks if the file exists in the images folder.
    If the file exists it sends the file to the browser.
    """
    # Sanitize the filename to prevent security issues.
    # secure_filename is a good first step.
    sanitized_filename = secure_filename(filename)

    # Basic input validation: ensure sanitized name is not empty
    # and matches the original to prevent requests like '/images/../'
    # which secure_filename might reduce to an empty string.
    if not sanitized_filename or sanitized_filename != filename:
        abort(400) # Bad Request

    # Use send_from_directory which is designed to be secure against
    # path traversal attacks. It will also handle 404 Not Found errors
    # if the file does not exist. It combines the check and open
    # in a safer way than manual checks.
    try:
        return send_from_directory(IMAGE_DIR, sanitized_filename, as_attachment=False)
    except FileNotFoundError:
        abort(404)

if __name__ == '__main__':
    # Setup: Create a directory and some dummy files for testing.
    if not os.path.exists(IMAGE_DIR):
        os.makedirs(IMAGE_DIR)
    
    with open(os.path.join(IMAGE_DIR, "test1.txt"), "w") as f:
        f.write("This is a test file.")
    with open(os.path.join(IMAGE_DIR, "test2.jpg"), "w") as f:
        f.write("This is a fake jpeg.")

    print("Server starting on port 5000...")
    print("Test cases:")
    print("1. Valid file: http://127.0.0.1:5000/images/test1.txt")
    print("2. Valid file with extension: http://127.0.0.1:5000/images/test2.jpg")
    print("3. Non-existent file: http://127.0.0.1:5000/images/nonexistent.png")
    print("4. Path traversal attempt (should be blocked): http://127.0.0.1:5000/images/../script.py")
    print("5. Path traversal with encoding (should be blocked): http://127.0.0.1:5000/images/%2e%2e/script.py")
    
    # Check if running in a test environment or otherwise.
    # For production, use a proper WSGI server instead of app.run()
    is_testing = 'pytest' in sys.modules
    if not is_testing:
        app.run(debug=False, port=5000)