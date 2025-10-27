# To run this code, first install Flask: pip install Flask
from flask import Flask, request, redirect, url_for, Response

app = Flask(__name__)

@app.route('/login', methods=['GET'])
def login():
    """Returns a login form."""
    form_html = """
    <html>
        <body>
            <h2>Login</h2>
            <form method="POST" action="/do_login">
                Username: <input type="text" name="username"><br>
                Password: <input type="password" name="password"><br>
                <input type="submit" value="Login">
            </form>
        </body>
    </html>
    """
    return form_html

@app.route('/do_login', methods=['POST'])
def do_login():
    """Processes the login form submission."""
    username = request.form.get('username')
    password = request.form.get('password')
    
    if username == 'admin' and password == 'admin':
        return redirect(url_for('admin_page'))
    else:
        return Response("Login Failed: Invalid credentials.", status=401)

@app.route('/admin_page')
def admin_page():
    """Displays the admin page."""
    return "<html><body><h1>Welcome, Admin!</h1></body></html>"

if __name__ == '__main__':
    port = 5000
    print(f"Python Flask server started on port {port}")
    print("--- 5 Test Cases ---")
    print(f"1. View login form: Open http://localhost:{port}/login in a browser or run: curl http://localhost:{port}/login")
    print(f"2. Successful login: curl -X POST -d \"username=admin&password=admin\" -L http://localhost:{port}/do_login")
    print(f"3. Failed login (wrong user): curl -X POST -d \"username=user&password=admin\" http://localhost:{port}/do_login")
    print(f"4. Failed login (wrong pass): curl -X POST -d \"username=admin&password=wrong\" http://localhost:{port}/do_login")
    print(f"5. View admin page directly: curl http://localhost:{port}/admin_page")
    app.run(debug=True, port=port)