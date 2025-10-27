
from flask import Flask, request, session, redirect, url_for
from functools import wraps
import uuid

class Lse55:
    def __init__(self):
        self.app = Flask(__name__)
        self.app.secret_key = 'your-secret-key-here'
        self.users = {
            'admin': {'password': 'admin123', 'role': 'admin'},
            'user1': {'password': 'pass123', 'role': 'user'},
            'user2': {'password': 'pass456', 'role': 'user'}
        }
        self.setup_routes()
    
    def setup_routes(self):
        self.app.add_url_rule('/login', 'login', self.login, methods=['GET'])
        self.app.add_url_rule('/do_login', 'do_login', self.do_login, methods=['POST'])
        self.app.add_url_rule('/index', 'index', self.index, methods=['GET'])
        self.app.add_url_rule('/', 'home', self.index, methods=['GET'])
        self.app.add_url_rule('/user_page', 'user_page', self.user_page, methods=['GET'])
        self.app.add_url_rule('/admin_page', 'admin_page', self.admin_page, methods=['GET'])
    
    # GET: Login page
    def login(self):
        return '''\n        <html>\n        <body>\n            <h2>Login Page</h2>\n            <form method="POST" action="/do_login">\n                Username: <input type="text" name="username"><br>\n                Password: <input type="password" name="password"><br>\n                <input type="submit" value="Login">\n            </form>\n        </body>\n        </html>\n        '''
    
    # POST: Process login
    def do_login(self):
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username in self.users:
            user = self.users[username]
            if user['password'] == password:
                session['username'] = username
                session['role'] = user['role']
                session['session_id'] = str(uuid.uuid4())
                return 'Login successful! <a href="/index">Go to Index</a>'
        
        return 'Login failed! Invalid credentials. <a href="/login">Try again</a>'
    
    # GET: Index/Home page
    def index(self):
        username = session.get('username')
        
        if username:
            return f'''\n            <html>\n            <body>\n                <h2>Welcome to the Index Page</h2>\n                <p>Hello, {username}!</p>\n                <a href="/user_page">User Page</a><br>\n                <a href="/admin_page">Admin Page</a>\n            </body>\n            </html>\n            '''
        
        return '''\n        <html>\n        <body>\n            <h2>Index Page</h2>\n            <p>Please <a href="/login">login</a> to continue.</p>\n        </body>\n        </html>\n        '''
    
    # GET: User page
    def user_page(self):
        username = session.get('username')
        
        if not username:
            return '''\n            <html>\n            <body>\n                <h2>Access Denied</h2>\n                <p>Please <a href="/login">login</a> first.</p>\n            </body>\n            </html>\n            '''
        
        return f'''\n        <html>\n        <body>\n            <h2>User Page</h2>\n            <p>Welcome, {username}!</p>\n            <p>This is your user dashboard.</p>\n            <a href="/index">Back to Index</a>\n        </body>\n        </html>\n        '''
    
    # GET: Admin page
    def admin_page(self):
        username = session.get('username')
        role = session.get('role')
        
        if not username:
            return '''\n            <html>\n            <body>\n                <h2>Access Denied</h2>\n                <p>Please <a href="/login">login</a> first.</p>\n            </body>\n            </html>\n            '''
        
        if role != 'admin':
            return '''\n            <html>\n            <body>\n                <h2>Access Denied</h2>\n                <p>You don't have admin privileges.</p>
                <a href="/index">Back to Index</a>
            </body>
            </html>
            '''
            return f'''
        <html>
        <body>
            <h2>Admin Page</h2>
            <p>Welcome, Administrator {username}!</p>
            <p>This is the admin control panel.</p>
            <a href="/index">Back to Index</a>
        </body>
        </html>
        '''
if __name__ == '__main__':
    print("Web Application Functions:")
    print("1. GET /login - Display login form")
    print("2. POST /do_login - Process login credentials")
    print("3. GET /index - Display home page")
    print("4. GET /user_page - Display user dashboard")
    print("5. GET /admin_page - Display admin panel")
    
    print("\\nTest Cases:")
    print("Test Case 1: Access login page - GET /login")
    print("Test Case 2: Login with admin - POST /do_login (username: admin, password: admin123)")
    print("Test Case 3: Access index page - GET /index")
    print("Test Case 4: Access user_page - GET /user_page")
    print("Test Case 5: Access admin_page with admin role - GET /admin_page")
    
    app = Lse55()
    # Uncomment to run the Flask application
    # app.app.run(debug=True)
