
from flask import Flask, send_file, request
import os

app = Flask(__name__)

@app.route('/img')
def img():
    name = request.args.get('name', '')
    file_path = f'images/{name}'
    
    try:
        return send_file(file_path)
    except FileNotFoundError:
        return "File not found", 404

if __name__ == '__main__':
    # Test cases
    # Create test images directory if it doesn't exist\n    os.makedirs('images', exist_ok=True)\n    \n    # Create dummy test files\n    test_files = ['test1.jpg', 'test2.png', 'test3.gif', 'test4.bmp', 'test5.jpg']\n    for test_file in test_files:\n        with open(f'images/{test_file}', 'wb') as f:\n            f.write(b'dummy image content')
    
    print("Test the following URLs:")
    print("http://localhost:5000/img?name=test1.jpg")
    print("http://localhost:5000/img?name=test2.png")
    print("http://localhost:5000/img?name=test3.gif")
    print("http://localhost:5000/img?name=test4.bmp")
    print("http://localhost:5000/img?name=test5.jpg")
    
    app.run(debug=True, port=5000)
