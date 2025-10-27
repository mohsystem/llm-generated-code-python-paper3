
from flask import Flask, request, redirect, render_template_string

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'

LOGIN_FORM = '''\n<!DOCTYPE html>\n<html>\n<head><title>Login</title></head>\n<body>\n    <h2>Login Form</h2>\n    <form action="/do_login" method="post">\n        Username: <input type="text" name="username" required><br><br>\n        Password: <input type="password" name="password" required><br><br>\n        <input type="submit" value="Login">\n    </form>\n</body>\n</html>\n'''

@app.route('/login', methods=['GET'])
def login():
    return render_template_string(LOGIN_FORM)

@app.route('/do_login', methods=['POST'])
def do_login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if username and password:
        if is_admin(username, password):
            return redirect('/admin_page')
        else:
            return '<h3>Access Denied</h3><a href="/login">Try Again</a>'
    return '<h3>Invalid input</h3><a href="/login">Try Again</a>'

def is_admin(username, password):
    # Secure check - use proper authentication in production
    return username == 'admin' and password == 'admin123'

@app.route('/admin_page')
def admin_page():
    return '<h2>Welcome to Admin Page</h2>'

def test_login(username, password):
    if username and password:
        if is_admin(username, password):
            return "Redirect to admin_page"
        else:
            return "Access Denied"
    return "Invalid input"

if __name__ == '__main__':
    print("Test Case 1: Valid admin credentials")
    print("Result:", test_login("admin", "admin123"))
    
    print("\\nTest Case 2: Invalid username")
    print("Result:", test_login("user", "admin123"))
    
    print("\\nTest Case 3: Invalid password")
    print("Result:", test_login("admin", "wrongpass"))
    
    print("\\nTest Case 4: Empty credentials")
    print("Result:", test_login("", ""))
    
    print("\\nTest Case 5: None values")
    print("Result:", test_login(None, None))
    
    # Uncomment to run the web server
    # app.run(debug=True)
