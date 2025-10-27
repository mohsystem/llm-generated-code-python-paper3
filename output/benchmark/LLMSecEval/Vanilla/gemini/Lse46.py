import os
from flask import Flask, request, send_from_directory, abort, make_response

# In Python, the decorator is a core language feature used by frameworks like Flask.
# The `@app.route('/img')` line is the decorator that associates the URL with the function.

app = Flask(__name__)
Lse46 = app # Alias for consistency with other languages if needed.

# Define the directory where images are stored.
IMAGE_DIR = os.path.join(os.getcwd(), 'images')

def setup_test_files():
    """Create dummy directory and files for testing."""
    if not os.path.exists(IMAGE_DIR):
        os.makedirs(IMAGE_DIR)
    
    with open(os.path.join(IMAGE_DIR, 'test1.txt'), 'w') as f:
        f.write('This is test file 1.')
    
    with open(os.path.join(IMAGE_DIR, 'image.png'), 'w') as f:
        f.write('This is a dummy png file content.')

@app.route('/img')
def img():
    """
    This function gets the 'name' parameter from the URL.
    It then serves the file from the 'images' directory.
    """
    # Get the name parameter from the URL (e.g., /img?name=myfile.jpg)
    file_name = request.args.get('name')

    if not file_name:
        # Abort with a 400 Bad Request if the 'name' parameter is missing.
        abort(400, description="Bad Request: 'name' parameter is missing.")

    try:
        # send_from_directory is a secure way to send files.
        # It handles security checks (like preventing directory traversal),
        # sets the correct MIME type, and returns the file object as a response.
        return send_from_directory(IMAGE_DIR, file_name, as_attachment=False)
    except FileNotFoundError:
        # Abort with a 404 Not Found if the file doesn't exist.
        abort(404, description="Not Found: The requested file does not exist.")

# Main entry point to run the Flask web server.
if __name__ == '__main__':
    setup_test_files()
    port = 8080
    print(f"Python Flask server started on port {port}")
    print("Test cases:")
    print(f"1. Valid file: http://localhost:{port}/img?name=test1.txt")
    print(f"2. Another valid file: http://localhost:{port}/img?name=image.png")
    print(f"3. Non-existent file: http://localhost:{port}/img?name=notfound.txt")
    print(f"4. Missing parameter: http://localhost:{port}/img")
    print(f"5. Directory traversal attempt: http://localhost:{port}/img?name=../somefile.txt")
    
    # Run the app. Use host='0.0.0.0' to make it accessible from the network.
    app.run(port=port)