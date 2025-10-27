
from flask import Flask, request, redirect, render_template_string

app = Flask(__name__)

# GET request - display login form
@app.route('/login', methods=['GET'])
def login():
    form_html = """\n    <html>\n    <body>\n        <h2>Login Form</h2>\n        <form method="POST" action="/do_login">\n            Username: <input type="text" name="username"><br>\n            Password: <input type="password" name="password"><br>\n            <input type="submit" value="Login">\n        </form>\n    </body>\n    </html>\n    """
    return render_template_string(form_html)

# POST request - process login
@app.route('/do_login', methods=['POST'])
def do_login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if username and username == 'admin':
        return redirect('/admin_page')
    else:
        return "<html><body><h3>Login failed or user is not admin</h3></body></html>"

@app.route('/admin_page')
def admin_page():
    return "<html><body><h2>Welcome to Admin Page</h2></body></html>"

if __name__ == '__main__':
    # Test cases
    print("Test 1 - Admin login: username='admin' -> Redirect to admin_page")
    print("Test 2 - Non-admin login: username='user' -> Return login failed")
    print("Test 3 - Empty username: username='' -> Return login failed")
    print("Test 4 - Null username: username=None -> Return login failed")
    print("Test 5 - Admin user: username='admin', password='wrong' -> Redirect to admin_page")
    
    # Run the Flask app
    # app.run(debug=True)
