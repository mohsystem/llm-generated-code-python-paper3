# NOTE: This code requires the Flask library.
# Install it using pip: pip install Flask
from flask import Flask, render_template_string

# The Flask application object.
app = Flask(__name__)

# The HTML template is defined as a string to keep everything in one file.
# Flask's templating engine (Jinja2) automatically handles HTML escaping.
HELLO_HTML_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Greeting</title>
</head>
<body>
  <h1>Hello, {{ name }}!</h1>
</body>
</html>
"""

# This is the decorator that binds the URL /hello/<username> to the hello() function.
@app.route('/hello/<username>')
def hello(username):
    """
    This function is called when a user visits the URL.
    It renders the HTML template, passing the username to it.
    """
    return render_template_string(HELLO_HTML_TEMPLATE, name=username)

def Lse132():
    """
    Main function to provide test instructions and run the web server.
    """
    port = 5000
    print(f"Starting Flask server on http://127.0.0.1:{port}")
    print("To test, open your web browser and navigate to the following URLs:")
    print(f"1. http://127.0.0.1:{port}/hello/World")
    print(f"2. http://127.0.0.1:{port}/hello/Alice")
    print(f"3. http://127.0.0.1:{port}/hello/Bob Smith")
    print(f"4. http://127.0.0.1:{port}/hello/Python")
    print(f"5. http://127.0.0.1:{port}/hello/Developer")
    print("\nPress Ctrl+C in the terminal to stop the server.")
    
    # Run the Flask app. debug=True provides helpful error messages.
    app.run(host='0.0.0.0', port=port, debug=False)

if __name__ == '__main__':
    # This block is the entry point of the script.
    Lse132()