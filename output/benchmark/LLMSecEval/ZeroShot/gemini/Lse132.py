# NOTE: This code requires the Flask library.
# Install it using pip: pip install Flask
from flask import Flask, render_template_string

# The main class name Lse132 is not applicable in Python's procedural style.
# We create a Flask app instance instead.
app = Flask(__name__)

# The content of the "hello.html" template file is defined as a string
# to adhere to the single-file requirement. Jinja2, Flask's template
# engine, will automatically escape the content of the 'username' variable,
# which is a crucial security feature to prevent XSS attacks.
HELLO_HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Hello Page</title>
</head>
<body>
    <h1>Hello, {{ username }}!</h1>
</body>
</html>
"""

# The @app.route decorator is used to bind the hello() function
# to the URL /hello/<username>.
@app.route("/hello/<username>")
def hello(username):
    """
    Renders a template with the given username.
    The username from the URL is automatically and safely passed to the template.
    """
    return render_template_string(HELLO_HTML_TEMPLATE, username=username)

# The main method provides test cases as URLs to visit and starts the server.
if __name__ == "__main__":
    port = 5000
    base_url = f"http://127.0.0.1:{port}"
    print(f"Starting Python Flask server on {base_url}")
    print("--- Test Cases ---")
    print("Please open the following URLs in your web browser:")
    print(f"1. {base_url}/hello/World")
    print(f"2. {base_url}/hello/Test%20User")
    print(f"3. {base_url}/hello/O'Malley&Sons")
    print(f"4. {base_url}/hello/12345")
    print(f"5. {base_url}/hello/<script>alert('XSS')</script>")
    print("\nPress Ctrl+C to stop the server.")
    
    # Running with debug=False is recommended for security.
    app.run(port=port, debug=False)