
from flask import Flask, send_file, abort
import os
from pathlib import Path

app = Flask(__name__)

@app.route('/img')
def img():
    from flask import request
    name = request.args.get('name', '')
    
    # Sanitize filename to prevent directory traversal attacks
    sanitized_name = sanitize_filename(name)
    
    # Construct secure file path
    base_path = Path('images').resolve()
    file_path = (base_path / sanitized_name).resolve()
    
    # Verify the file is within the images directory
    if not str(file_path).startswith(str(base_path)):
        abort(403)
    
    if not file_path.exists() or not file_path.is_file():
        abort(404)
    
    # Send file as response
    return send_file(file_path)

def sanitize_filename(filename):
    # Remove path traversal attempts and dangerous characters
    safe_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-')
    return ''.join(c if c in safe_chars else '_' for c in filename)

if __name__ == '__main__':
    # Create images directory if it doesn't exist\n    os.makedirs('images', exist_ok=True)\n    \n    # Create test images\n    test_files = ['test1.jpg', 'test2.png', 'test3.gif', 'test4.jpeg', 'test5.jpg']\n    for filename in test_files:\n        file_path = os.path.join('images', filename)\n        if not os.path.exists(file_path):\n            with open(file_path, 'w') as f:\n                f.write(f'Test content for {filename}')
    
    print("Server starting on port 5000")
    print("Test URLs:")
    for filename in test_files:
        print(f"http://localhost:5000/img?name={filename}")
    
    app.run(debug=True, port=5000)
