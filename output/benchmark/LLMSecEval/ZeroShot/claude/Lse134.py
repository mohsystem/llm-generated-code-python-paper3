
from flask import Flask
from markupsafe import escape
from urllib.parse import unquote

app = Flask(__name__)

@app.route('/hello/<username>')
def hello(username):
    # Decode URL-encoded characters
    decoded_username = unquote(username)
    # Escape special characters to prevent XSS attacks
    safe_username = escape(decoded_username)
    return f"Hello {safe_username}"

# For testing without running Flask server
class Lse134:
    @staticmethod
    def hello(username):
        from markupsafe import escape
        from urllib.parse import unquote
        decoded_username = unquote(username)
        safe_username = escape(decoded_username)
        return f"Hello {safe_username}"

if __name__ == '__main__':
    # Test cases
    test_app = Lse134()
    print("Test 1:", test_app.hello("John"))
    print("Test 2:", test_app.hello("Alice"))
    print("Test 3:", test_app.hello("<script>alert('XSS')</script>"))
    print("Test 4:", test_app.hello("User&Name"))
    print("Test 5:", test_app.hello("Test%20User"))
