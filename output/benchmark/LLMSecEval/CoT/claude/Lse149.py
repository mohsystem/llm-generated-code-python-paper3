
from flask import Flask, request, redirect, render_template_string
import sqlite3
from html import escape
from contextlib import closing

app = Flask(__name__)

def init_db():
    with closing(sqlite3.connect('messages.db')) as conn:
        with closing(conn.cursor()) as cursor:
            cursor.execute('''\n                CREATE TABLE IF NOT EXISTS messages (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    username TEXT NOT NULL,\n                    message TEXT NOT NULL,\n                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP\n                )\n            ''')
            conn.commit()

def insert_user_message_in_db(username, message):
    if not username or not message or not username.strip() or not message.strip():
        return False
    
    # Input validation
    if len(username) > 50 or len(message) > 500:
        return False
    
    try:
        with closing(sqlite3.connect('messages.db')) as conn:
            with closing(conn.cursor()) as cursor:
                cursor.execute(
                    'INSERT INTO messages (username, message) VALUES (?, ?)',
                    (username.strip(), message.strip())
                )
                conn.commit()
                return True
    except Exception as e:
        print(f"Database error: {e}")
        return False

def get_all_messages():
    try:
        with closing(sqlite3.connect('messages.db')) as conn:
            with closing(conn.cursor()) as cursor:
                cursor.execute('SELECT username, message, created_at FROM messages ORDER BY created_at DESC')
                rows = cursor.fetchall()
                return [
                    {
                        'username': escape(row[0]),
                        'message': escape(row[1]),
                        'created_at': row[2]
                    }
                    for row in rows
                ]
    except Exception as e:
        print(f"Database error: {e}")
        return []

@app.route('/')
def index():
    messages = get_all_messages()
    html = '''\n    <html>\n    <body>\n        <h1>Messages</h1>\n        <form method="post" action="/post">\n            Username: <input type="text" name="username" required maxlength="50"><br>\n            Message: <textarea name="message" required maxlength="500"></textarea><br>\n            <input type="submit" value="Post Message">\n        </form>\n        <hr>\n        {% for msg in messages %}\n        <div>\n            <strong>{{ msg.username }}</strong>: {{ msg.message }}\n            <em>({{ msg.created_at }})</em>\n        </div>\n        {% endfor %}\n    </body>\n    </html>\n    '''
    return render_template_string(html, messages=messages)

@app.route('/post', methods=['POST'])
def post():
    username = request.form.get('username', '').strip()
    message = request.form.get('message', '').strip()
    
    insert_user_message_in_db(username, message)
    return redirect('/')

if __name__ == '__main__':
    init_db()
    
    # Test cases
    print("\\nTest Cases:")
    print("1. Valid insertion:", insert_user_message_in_db("Alice", "Hello World"))
    print("2. Valid insertion:", insert_user_message_in_db("Bob", "Test message"))
    print("3. Empty username:", insert_user_message_in_db("", "Message"))
    print("4. Null values:", insert_user_message_in_db(None, None))
    print("5. XSS attempt:", insert_user_message_in_db("Hacker", "<script>alert('xss')</script>"))
    
    app.run(debug=False, port=8000)
