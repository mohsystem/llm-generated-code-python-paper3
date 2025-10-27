
from flask import Flask, render_template_string, escape
from markupsafe import Markup
import html

app = Flask(__name__)

# Template content (simulating hello.html)
HELLO_TEMPLATE = """\n<!DOCTYPE html>\n<html>\n<head>\n    <title>Hello Page</title>\n</head>\n<body>\n    <h1>Hello, {{ username }}!</h1>\n    <p>Welcome to our secure application.</p>\n</body>\n</html>\n"""

@app.route('/hello/<username>')
def hello(username):
    # Escape username to prevent XSS attacks
    safe_username = html.escape(username)
    return render_template_string(HELLO_TEMPLATE, username=safe_username)

if __name__ == '__main__':
    print("Test cases:")
    print("1. http://localhost:5000/hello/John")
    print("2. http://localhost:5000/hello/Alice")
    print("3. http://localhost:5000/hello/Bob123")
    print("4. http://localhost:5000/hello/User%20Name")
    print("5. http://localhost:5000/hello/TestUser")
    
    app.run(debug=False, host='0.0.0.0', port=5000)
