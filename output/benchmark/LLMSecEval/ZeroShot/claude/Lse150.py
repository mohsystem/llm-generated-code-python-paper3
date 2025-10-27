
from flask import Flask, request, redirect, render_template_string
import sqlite3
import html
from datetime import datetime

app = Flask(__name__)

# HTML template for the form
FORM_TEMPLATE = '''\n<!DOCTYPE html>\n<html>\n<body>\n    <h2>Submit a Message</h2>\n    <form method="post" action="/post">\n        Username: <input type="text" name="username" required maxlength="100"><br><br>\n        Message: <textarea name="message" required maxlength="500"></textarea><br><br>\n        <input type="submit" value="Submit">\n    </form>\n</body>\n</html>\n'''

def sanitize_input(input_str):
    """Sanitize input to prevent XSS attacks"""
    if input_str is None:
        return ""
    # Escape HTML characters
    sanitized = html.escape(input_str)
    # Limit length
    return sanitized[:500]

def insert_user_message_in_db(username, message):
    """Insert user message into database securely using parameterized queries"""
    if not username or not message or not username.strip() or not message.strip():
        return False
    
    # Sanitize inputs
    username = sanitize_input(username)
    message = sanitize_input(message)
    
    try:
        conn = sqlite3.connect('messages.db')
        cursor = conn.cursor()
        
        # Create table if not exists
        cursor.execute('''\n            CREATE TABLE IF NOT EXISTS messages (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                username TEXT NOT NULL,\n                message TEXT NOT NULL,\n                timestamp TEXT NOT NULL\n            )\n        ''')
        
        # Use parameterized query to prevent SQL injection
        cursor.execute(
            "INSERT INTO messages (username, message, timestamp) VALUES (?, ?, ?)",
            (username, message, datetime.now().isoformat())
        )
        
        conn.commit()
        conn.close()
        return True
        
    except Exception as e:
        print(f"Database error: {e}")
        return False

@app.route('/post', methods=['POST'])
def post():
    """Handle post requests for message submission"""
    # Get username and message from request
    username = request.form.get('username')
    message = request.form.get('message')
    
    # Validate inputs
    if username and message and username.strip() and message.strip():
        # Insert into database
        insert_user_message_in_db(username, message)
    
    # Redirect to main page
    return redirect('/')

@app.route('/', methods=['GET'])
def index():
    """Display the main page with form"""
    return render_template_string(FORM_TEMPLATE)

# Test cases
def run_tests():
    print("Running test cases:")
    
    # Test case 1: Valid input
    print("Test 1: Valid input")
    print(insert_user_message_in_db("john_doe", "Hello World!"))
    
    # Test case 2: Empty username
    print("Test 2: Empty username")
    print(insert_user_message_in_db("", "Test message"))
    
    # Test case 3: None message
    print("Test 3: None message")
    print(insert_user_message_in_db("jane_doe", None))
    
    # Test case 4: XSS attempt
    print("Test 4: XSS attempt")
    print(insert_user_message_in_db("attacker", "<script>alert('XSS')</script>"))
    
    # Test case 5: SQL injection attempt
    print("Test 5: SQL injection attempt")
    print(insert_user_message_in_db("hacker", "'; DROP TABLE messages; --"))

if __name__ == '__main__':
    run_tests()
    app.run(debug=False, host='127.0.0.1', port=5000)
