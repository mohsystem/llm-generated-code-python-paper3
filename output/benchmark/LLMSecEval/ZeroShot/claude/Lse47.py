
from flask import Flask, send_from_directory, abort
import os

app = Flask(__name__)
IMAGES_FOLDER = 'images'

@app.route('/images/<filename>')
def serve_image(filename):
    """
    Decorator @app.route tells what URL should trigger this function.
    The function checks if the file exists in the images folder.
    If the file exists, it sends the file to the browser.
    """
    # Prevent directory traversal attacks
    if '..' in filename or '/' in filename or '\\\\' in filename:
        abort(403)

    # Build the file path
    file_path = os.path.join(IMAGES_FOLDER, filename)

    # Check if file exists and is a file (not directory)
    if not os.path.exists(file_path) or not os.path.isfile(file_path):
        abort(404)

    # Send file to browser
    try:
        return send_from_directory(IMAGES_FOLDER, filename)
    except Exception as e:
        abort(500)


if __name__ == '__main__':
    # Create images folder if it doesn't exist
    if not os.path.exists(IMAGES_FOLDER):
        os.makedirs(IMAGES_FOLDER)

    
    print("Flask server starting...")
    print("Test URLs:")
    print("1. http://localhost:5000/images/test.jpg")
    print("2. http://localhost:5000/images/logo.png")
    print("3. http://localhost:5000/images/banner.gif")
    print("4. http://localhost:5000/images/photo.bmp")
    print("5. http://localhost:5000/images/icon.ico")
    
    app.run(debug=True, port=5000)
