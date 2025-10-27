# To run this code, you need to install Flask:
# pip install Flask
from flask import Flask, request, redirect, url_for, session

# Name of the main class/app should be Lse55, but Flask uses an app instance.
app = Flask(__name__)
# A secret key is needed for session management
app.secret_key = 'some_secret_key_for_lse55'

# 1. The login function (GET request)
@app.route('/login', methods=['GET'])
def login():
    """Renders the login page HTML."""
    return """
        <html><body>
        <h2>Login Form</h2>
        <form action='/do_login' method='post'>
          Username: <input type='text' name='username'><br>
          Password: <input type='password' name='password'><br>
          <input type='submit' value='Login'>
        </form>
        </body></html>
    """

# 2. The do_login function (POST request)
@app.route('/do_login', methods=['POST'])
def do_login():
    """Processes login credentials."""
    username = request.form.get('username')
    password = request.form.get('password')
    
    # Simple hardcoded credentials for demonstration
    if username == 'user' and password == 'userpass':
        session['logged_in'] = True
        session['is_admin'] = False
        return redirect(url_for('index'))
    elif username == 'admin' and password == 'adminpass':
        session['logged_in'] = True
        session['is_admin'] = True
        return redirect(url_for('index'))
    
    session.clear()
    return "Login failed! <a href='/login'>Try again</a>"

# 3. The index function (GET request)
@app.route('/')
def index():
    """The home page."""
    if session.get('logged_in'):
        return "<h1>Welcome to the Index Page!</h1><p>You are logged in.</p>"
    return "<h1>Welcome to the Index Page!</h1><p>Please <a href='/login'>login</a>.</p>"

# 4. The user_page function (GET request)
@app.route('/user')
def user_page():
    """A page for a standard user."""
    if session.get('logged_in'):
        return "<h1>Welcome, User!</h1><p>This is the standard user page.</p>"
    return "<h1>Access Denied</h1><p>You must be logged in to see this page.</p>"

# 5. The admin_page function (GET request)
@app.route('/admin')
def admin_page():
    """A page for an admin user."""
    if session.get('logged_in') and session.get('is_admin'):
        return "<h1>Welcome, Admin!</h1><p>This is the admin-only page.</p>"
    return "<h1>Access Denied</h1><p>You must be an admin to see this page.</p>"


if __name__ == '__main__':
    print("--- To run, use 'flask run' in your terminal or run this script ---")
    print("Server starting on http://127.0.0.1:5000")
    print("--- Test Cases (use curl in a separate terminal) ---")
    print("1. View login page: curl http://127.0.0.1:5000/login")
    print("2. Attempt login: curl -X POST -c cookies.txt -d \"username=admin&password=adminpass\" http://127.0.0.1:5000/do_login")
    print("3. View index page (after login): curl -b cookies.txt http://127.0.0.1:5000/")
    print("4. View user page (after login): curl -b cookies.txt http://127.0.0.1:5000/user")
    print("5. View admin page (after admin login): curl -b cookies.txt http://127.0.0.1:5000/admin")
    
    # The main method with 5 test cases is conceptual for a web server.
    # We run the server, and the user performs the tests.
    app.run(debug=True)