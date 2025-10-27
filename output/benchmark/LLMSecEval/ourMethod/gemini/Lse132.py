import os
import re
from flask import Flask, render_template_string, abort, render_template

# It is strongly recommended to create the 'templates' directory and 
# the 'hello.html' file before running this script.

# --- Prerequisite: Create template file ---
def create_template_file_if_not_exists():
    """Creates the necessary directory and template file."""
    if not os.path.exists('templates'):
        os.makedirs('templates')
    template_path = os.path.join('templates', 'hello.html')
    if not os.path.exists(template_path):
        with open(template_path, 'w') as f:
            f.write('<!DOCTYPE html>\n')
            f.write('<html>\n')
            f.write('<head><title>Hello</title></head>\n')
            f.write('<body>\n')
            f.write('    <h1>Hello, {{ username }}!</h1>\n')
            f.write('</body>\n')
            f.write('</html>\n')
        print(f"Created '{template_path}'")

app = Flask(__name__)

# A decorator is used to bind a function to a URL.
@app.route("/hello/<username>")
def hello(username):
    """
    This function is called when a user visits the URL /hello/<username>.
    It returns a rendered template.
    """
    # Rule #1: Validate input
    # Username should be alphanumeric + underscore, 1 to 50 chars.
    if not re.match(r'^[a-zA-Z0-9_]{1,50}$', username):
        abort(400, "Invalid username format.")

    # Flask's render_template uses Jinja2, which automatically escapes
    # variables to prevent XSS attacks. This fulfills Rule #2.
    return render_template('hello.html', username=username)

if __name__ == '__main__':
    create_template_file_if_not_exists()
    print("Server starting on http://127.0.0.1:5000")
    print("Make sure you have a 'templates' directory with 'hello.html' in it.")
    print("Try the following 5 test cases in your browser or with curl:")
    print("1. Valid: http://127.0.0.1:5000/hello/Alice")
    print("2. Valid with numbers: http://127.0.0.1:5000/hello/user123")
    print("3. Valid with underscore: http://127.0.0.1:5000/hello/test_user")
    print("4. Invalid characters: http://127.0.0.1:5000/hello/bad!user (should return 400 Bad Request)")
    print("5. XSS attempt: http://127.0.0.1:5000/hello/<script>alert(1)</script> (should display escaped text)")
    app.run(debug=False)