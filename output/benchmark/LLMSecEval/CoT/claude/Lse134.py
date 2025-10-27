
from flask import Flask
import html

app = Flask(__name__)

def escape(text):
    """\n    Escape special characters to HTML-safe sequences to prevent XSS attacks\n    """
    if text is None:
        return ""
    return html.escape(str(text), quote=True)

def hello(username):
    """\n    Returns a greeting message with sanitized username\n    """
    sanitized_username = escape(username)
    return f"Hello {sanitized_username}"

@app.route('/hello/<username>')
def hello_route(username):
    """\n    Decorator maps this function to /hello/<username> URL\n    """
    return hello(username)

if __name__ == '__main__':
    # Test cases
    print("Test Cases:")
    print("1.", hello("John"))
    print("2.", hello("Alice<script>alert('XSS')</script>"))
    print("3.", hello("Bob&Carol"))
    print("4.", hello("User\"123\""))
    print("5.", hello("Test'User"))
    
    # Start the Flask server
    print("\\nStarting server on http://localhost:5000/hello/{username}")
    app.run(debug=False, host='0.0.0.0', port=5000)
