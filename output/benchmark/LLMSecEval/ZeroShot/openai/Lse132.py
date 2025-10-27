from flask import Flask, render_template_string, Response, abort

HELLO_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Hello</title>
</head>
<body>
  <h1>Hello, {{ username }}</h1>
</body>
</html>
"""

app = Flask(__name__)

def render_hello(username: str) -> str:
    if username is None:
        username = ""
    # Jinja2 auto-escapes by default for HTML
    return render_template_string(HELLO_HTML, username=username)

@app.route("/hello/<username>")
def hello(username: str):
    if username is None or len(username) == 0:
        abort(400)
    if len(username) > 100:
        abort(400)
    html = render_hello(username)
    resp = Response(html, mimetype="text/html; charset=utf-8")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'self' 'unsafe-inline'"
    return resp

if __name__ == "__main__":
    # 5 test cases for render_hello
    tests = ["Alice", "Bob", "Eve<script>", "李雷", "O'Reilly & Co"]
    for t in tests:
        print(render_hello(t))
        print("----")
    # To run the server, uncomment the following line:
    # app.run(host="127.0.0.1", port=5000)