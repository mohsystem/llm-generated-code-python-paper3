from flask import Flask, render_template, abort
import os
import re
import tempfile

# Security: validate usernames strictly
USERNAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")

def is_valid_username(username: str) -> bool:
    if not isinstance(username, str):
        return False
    if not (1 <= len(username) <= 32):
        return False
    return bool(USERNAME_RE.fullmatch(username))

# Prepare a secure temporary templates directory and write hello.html
_templates_dir = tempfile.mkdtemp(prefix="lse132_templates_")
_hello_path = os.path.join(_templates_dir, "hello.html")
_template_html = """<!doctype html>
<html>
<head><meta charset="utf-8"><title>Hello</title></head>
<body>
  <h1>Hello, {{ username }}</h1>
</body>
</html>
"""
with open(_hello_path, "w", encoding="utf-8") as f:
    f.write(_template_html)

app = Flask(__name__, template_folder=_templates_dir)

# Decorator binds the function to the URL /hello/<username>
@app.route("/hello/<username>")
def hello(username: str):
    if not is_valid_username(username):
        abort(400)
    # Jinja2 escapes user input by default in HTML context
    return render_template("hello.html", username=username)

# Test function to render without HTTP
def render_hello_direct(username: str) -> str:
    if not is_valid_username(username):
        return "Invalid username"
    return render_template("hello.html", username=username)

if __name__ == "__main__":
    # 5 test cases using Flask test client
    test_usernames = ["Alice", "bob_123", "user-01", "X", "Z9_9-_"]
    with app.test_client() as client:
        for u in test_usernames:
            resp = client.get(f"/hello/{u}")
            print(f"---- Test: {u} ----")
            print(resp.get_data(as_text=True))
    # To run the server instead of tests, uncomment:
    # app.run(host="127.0.0.1", port=5000, debug=False)