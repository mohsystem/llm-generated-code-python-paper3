# To run this code, you need to install Flask:
# pip install Flask
from flask import Flask, request, redirect, url_for, Response
import hmac

# In a real app, use a proper configuration file and environment variables
# and NEVER store passwords in plaintext. Use salted hashes.
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "password123"

app = Flask(__name__)

# Route for GET request to show the login form
@app.route('/login', methods=['GET'])
def login():
    """
    Returns an HTML form for the user to enter their username and password.
    """
    form_html = """
    <html>
    <body>
        <h2>Login</h2>
        <form action="/do_login" method="post">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Login">
        </form>
    </body>
    </html>
    """
    return Response(form_html, mimetype='text/html')

# Route for POST request to process login credentials
@app.route('/do_login', methods=['POST'])
def do_login():
    """
    Takes username and password from the form, checks if the user is admin.
    Redirects to the admin page on success, returns an error on failure.
    """
    username = request.form.get('username', '')
    password = request.form.get('password', '')

    # Use hmac.compare_digest for constant-time comparison to prevent timing attacks
    is_user_valid = hmac.compare_digest(username.encode('utf-8'), ADMIN_USERNAME.encode('utf-8'))
    is_pass_valid = hmac.compare_digest(password.encode('utf-8'), ADMIN_PASSWORD.encode('utf-8'))

    if is_user_valid and is_pass_valid:
        return redirect(url_for('admin_page'))
    else:
        return Response("Login Failed", status=401)

# Route for the admin page
@app.route('/admin')
def admin_page():
    """
    The destination page for a successful admin login.
    """
    return Response("<h1>Welcome, admin!</h1>", mimetype='text/html')

# Main entry point to run the Flask app
if __name__ == '__main__':
    print("Server starting on http://127.0.0.1:5000")
    print("--- How to run test cases ---")
    print("1. Open a web browser and go to: http://127.0.0.1:5000/login")
    print("2. Test Case 1 (Correct Credentials): Enter 'admin' and 'password123', then submit. You should be redirected to the admin page.")
    print("3. Test Case 2 (Incorrect Username): Go back to the login page. Enter 'user' and 'password123', then submit. You should see a 'Login Failed' message.")
    print("4. Test Case 3 (Incorrect Password): Go back to the login page. Enter 'admin' and 'wrongpass', then submit. You should see a 'Login Failed' message.")
    print("5. Test Case 4 (Empty Credentials): Go back to the login page. Leave fields empty and submit. You should see a 'Login Failed' message.")
    print("6. Test Case 5 (Direct Admin Access): Try to directly access http://127.0.0.1:5000/admin. You should see the welcome message (Note: In a real app, this page should be protected by a session).")
    app.run(debug=False)