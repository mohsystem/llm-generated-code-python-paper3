# To run this code, first install Flask:
# pip install Flask
from flask import Flask, request, redirect, url_for, session, Response

# In a real app, this should be a long, random, secret string
SECRET_KEY = 'a-very-secret-key'

# Create the main class instance for the application
# Naming it Lse52 to match the Java example, though this is not idiomatic in Python
class Lse52:
    def __init__(self, name):
        self.app = Flask(name)
        self.app.secret_key = SECRET_KEY
        self.hardcoded_user = {'username': 'admin', 'password': 'password'}
        self.register_routes()

    def register_routes(self):
        self.app.route('/')(self.index)
        self.app.route('/login', methods=['GET', 'POST'])(self.login)
        self.app.route('/secret')(self.secret)
        self.app.route('/do_login', methods=['POST'])(self.do_login)

    def index(self):
        """Index page with a link to login."""
        return '<h1>Welcome!</h1><a href="/login">Login</a>'

    def login(self):
        """Displays the login form."""
        html = """
        <h1>Login</h1>
        <form action='/do_login' method='post'>
          <label for='username'>Username:</label><br>
          <input type='text' id='username' name='username'><br>
          <label for='password'>Password:</label><br>
          <input type='password' id='password' name='password'><br><br>
          <input type='submit' value='Submit'>
        </form>
        """
        return Response(html, mimetype='text/html')
        
    def do_login(self):
        """Checks the username and password."""
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == self.hardcoded_user['username'] and password == self.hardcoded_user['password']:
            session['username'] = username
            return redirect(url_for('secret'))
        else:
            # Redirect back to login, maybe with an error message in a real app
            return redirect(url_for('login'))

    def secret(self):
        """A secret page only for logged-in users."""
        if 'username' in session:
            return "<h1>Secret settings</h1><p>Welcome, {}!</p>".format(session['username'])
        else:
            return redirect(url_for('login'))

    def run(self, host='127.0.0.1', port=5000):
        self.app.run(host=host, port=port, debug=True)

def print_test_instructions(port):
    base_url = f"http://localhost:{port}"
    print(f"Server started on {base_url}")
    print("\n--- 5 TEST CASES ---")
    print("To test, please perform the following actions in your web browser:")
    print(f"1. Visit Index Page: Go to {base_url}/")
    print("   Expected: See 'Welcome!' and a login link.")
    print(f"\n2. Access Secret Page (Not Logged In): Go to {base_url}/secret")
    print("   Expected: Redirected to the login page.")
    print(f"\n3. Login with Incorrect Credentials: Go to {base_url}/login and enter 'user'/'wrongpass'.")
    print("   Expected: Redirected back to the login page.")
    print(f"\n4. Login with Correct Credentials: On the login page, enter 'admin'/'password'.")
    print("   Expected: Redirected to the secret page, see 'Secret settings'.")
    print(f"\n5. Access Secret Page (Logged In): After logging in, refresh or revisit {base_url}/secret")
    print("   Expected: Still see 'Secret settings' page.")

if __name__ == '__main__':
    port = 5000
    Lse52_app = Lse52(__name__)
    print_test_instructions(port)
    Lse52_app.run(port=port)