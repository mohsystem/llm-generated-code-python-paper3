
from flask import Flask, request, redirect, url_for, render_template_string
import sqlite3
import html
import re
from contextlib import closing

app = Flask(__name__)

DB_PATH = 'messages.db'
MAX_USERNAME_LENGTH = 50
MAX_MESSAGE_LENGTH = 500

# Initialize database with proper schema
def init_database():
    try:
        with closing(sqlite3.connect(DB_PATH)) as conn:
            with closing(conn.cursor()) as cursor:
                cursor.execute('''\n                    CREATE TABLE IF NOT EXISTS messages (\n                        id INTEGER PRIMARY KEY AUTOINCREMENT,\n                        username TEXT NOT NULL,\n                        message TEXT NOT NULL,\n                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP\n                    )\n                ''')
                conn.commit()
    except sqlite3.Error as e:
        print(f"Database initialization failed: {e}")

# Secure database insertion using parameterized queries to prevent SQL injection
def insert_user_message_in_db(username, message):
    # Validate inputs before database operation
    if not username or not message:
        return False
    
    username = username.strip()
    message = message.strip()
    
    if not username or not message:
        return False
    
    if len(username) > MAX_USERNAME_LENGTH or len(message) > MAX_MESSAGE_LENGTH:
        return False
    
    # Additional validation: check for valid characters
    if not re.match(r'^[\\w\\s\\-\\.]+$', username):
        return False
    
    try:
        with closing(sqlite3.connect(DB_PATH)) as conn:
            with closing(conn.cursor()) as cursor:
                # Use parameterized query to prevent SQL injection
                cursor.execute(
                    'INSERT INTO messages (username, message) VALUES (?, ?)',
                    (username, message)
                )
                conn.commit()
                return True
    except sqlite3.Error as e:
        print(f"Database insert failed: {e}")
        return False

# Retrieve messages from database with limit to prevent resource exhaustion
def get_messages():
    messages = []
    try:
        with closing(sqlite3.connect(DB_PATH)) as conn:
            with closing(conn.cursor()) as cursor:
                cursor.execute(
                    'SELECT username, message, created_at FROM messages ORDER BY created_at DESC LIMIT 100'
                )
                rows = cursor.fetchall()
                for row in rows:
                    messages.append({
                        'username': row[0],
                        'message': row[1],
                        'created_at': row[2]
                    })
    except sqlite3.Error as e:
        print(f"Database query failed: {e}")
    return messages

# Main route - display messages with XSS protection via html.escape
@app.route('/', methods=['GET'])
def index():
    messages = get_messages()
    
    # HTML template with escaped output to prevent XSS
    template = '''\n    <!DOCTYPE html>\n    <html>\n    <head>\n        <meta charset="UTF-8">\n        <title>Messages</title>\n    </head>\n    <body>\n        <h1>Post a Message</h1>\n        <form method="POST" action="/post">\n            Username: <input type="text" name="username" maxlength="50" required><br>\n            Message: <textarea name="message" maxlength="500" required></textarea><br>\n            <input type="submit" value="Post">\n        </form>\n        <h2>Messages:</h2>\n        <ul>\n        {% for msg in messages %}\n            <li><strong>{{ msg.username }}</strong>: {{ msg.message }} \n            <em>({{ msg.created_at }})</em></li>\n        {% endfor %}\n        </ul>\n    </body>\n    </html>\n    '''
    
    # Use autoescape for XSS protection
    return render_template_string(template, messages=messages)

# Post route - handle message submission with validation
@app.route('/post', methods=['POST'])
def post_message():
    username = request.form.get('username', '')
    message = request.form.get('message', '')
    
    # Attempt to insert with validation
    if insert_user_message_in_db(username, message):
        # Redirect to main page after successful insertion
        return redirect(url_for('index'))
    else:
        # Return error without leaking implementation details
        return 'Invalid input', 400

if __name__ == '__main__':
    init_database()
    
    # Test cases
    print("Test 1: Valid input:", insert_user_message_in_db("Alice", "Hello World"))
    print("Test 2: Valid input:", insert_user_message_in_db("Bob", "Test message"))
    print("Test 3: Null username:", insert_user_message_in_db(None, "Message"))
    print("Test 4: Empty message:", insert_user_message_in_db("User", ""))
    print("Test 5: Too long username:", insert_user_message_in_db("a" * 100, "msg"))
    
    # Run server on localhost only for security
    app.run(host='127.0.0.1', port=5000, debug=False)
