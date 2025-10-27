from flask import Flask, render_template
import os

app = Flask(__name__, template_folder='templates')

def _ensure_template():
    os.makedirs('templates', exist_ok=True)
    path = os.path.join('templates', 'hello.html')
    if not os.path.exists(path):
        with open(path, 'w', encoding='utf-8') as f:
            f.write("""<!doctype html>
<html>
<head><title>Hello</title></head>
<body>
<h1>Hello, {{ username }}!</h1>
</body>
</html>
""")

# Decorator binds function to URL /hello/<username>
@app.route('/hello/<username>')
def hello(username):
    return render_template('hello.html', username=username)

def handle_request_for_tests(url):
    # Simple test-only router to emulate calls without running server
    # Accepts URLs like /hello/<username>
    import re
    m = re.match(r'^/hello/([^/]+)$', url)
    if m:
        return hello(m.group(1))
    return "404 Not Found"

if __name__ == '__main__':
    _ensure_template()
    # 5 test cases using Flask test client
    with app.test_client() as client:
        tests = [
            "/hello/alice",
            "/hello/Bob",
            "/hello/charlie_123",
            "/hello/Dana-XYZ",
            "/hello/Eve"
        ]
        for url in tests:
            resp = client.get(url)
            print("URL:", url)
            print(resp.get_data(as_text=True))
            print("-----")