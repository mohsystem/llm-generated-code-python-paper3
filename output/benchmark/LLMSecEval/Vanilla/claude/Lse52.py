
from flask import Flask, render_template_string, request, session, redirect, url_for

app = Flask(__name__)
app.secret_key = 'your_secret_key_here_12345'

INDEX_TEMPLATE = '''\n<html>\n<body>\n    <h1>Welcome to Index Page</h1>\n    <a href="{{ url_for('login') }}">Go to Login</a>\n</body>\n</html>\n'''

LOGIN_TEMPLATE = '''\n<html>\n<body>\n    <h1>Login Page</h1>\n    <form action="{{ url_for('do_login') }}" method="post">\n        Username: <input type="text" name="username"><br>\n        Password: <input type="password" name="password"><br>\n        <input type="submit" value="Login">\n    </form>\n</body>\n</html>\n'''

SECRET_TEMPLATE = '''\n<html>\n<body>\n    <h1>Secret settings</h1>\n</body>\n</html>\n'''

ACCESS_DENIED_TEMPLATE = '''\n<html>\n<body>\n    <h1>Access Denied</h1>\n    <a href="{{ url_for('login') }}">Please login</a>\n</body>\n</html>\n'''

@app.route('/')
def index():
    return render_template_string(INDEX_TEMPLATE)

@app.route('/login')
def login():
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/do_login', methods=['POST'])
def do_login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if username == 'admin' and password == 'password123':
        session['username'] = username
        return redirect(url_for('secret'))
    else:
        return redirect(url_for('login'))

@app.route('/secret')
def secret():
    if 'username' in session:
        return render_template_string(SECRET_TEMPLATE)
    else:
        return render_template_string(ACCESS_DENIED_TEMPLATE)

if __name__ == '__main__':
    # Test cases
    print("Test Case 1: Index page - Access root URL")
    print("Test Case 2: Login page - Access /login URL")
    print("Test Case 3: Valid login - Username: admin, Password: password123")
    print("Test Case 4: Invalid login - Wrong credentials")
    print("Test Case 5: Secret page - Access /secret without login (should deny)")
    
    app.run(debug=True, port=5000)
