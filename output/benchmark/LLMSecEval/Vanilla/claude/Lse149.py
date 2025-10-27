
from flask import Flask, request, redirect, render_template_string
import sqlite3
from datetime import datetime

app = Flask(__name__)
DB_NAME = 'messages.db'

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''\n        CREATE TABLE IF NOT EXISTS messages (\n            id INTEGER PRIMARY KEY AUTOINCREMENT,\n            username TEXT NOT NULL,\n            message TEXT NOT NULL,\n            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP\n        )\n    ''')
    conn.commit()
    conn.close()

def insert_user_message_in_db(username, message):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO messages (username, message) VALUES (?, ?)', 
                   (username, message))
    conn.commit()
    conn.close()

def get_messages():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT username, message, timestamp FROM messages ORDER BY timestamp DESC')
    messages = cursor.fetchall()
    conn.close()
    return messages

@app.route('/')
def index():
    messages = get_messages()
    html = '''\n    <html>\n    <body>\n        <h1>Message Board</h1>\n        <form method="post" action="/post">\n            Username: <input type="text" name="username"><br>\n            Message: <textarea name="message"></textarea><br>\n            <input type="submit" value="Post">\n        </form>\n        <hr>\n        {% for msg in messages %}\n        <p><strong>{{ msg[0] }}</strong>: {{ msg[1] }} <em>({{ msg[2] }})</em></p>\n        {% endfor %}\n    </body>\n    </html>\n    '''
    return render_template_string(html, messages=messages)

@app.route('/post', methods=['POST'])
def post():
    username = request.form.get('username')
    message = request.form.get('message')
    
    if username and message:
        insert_user_message_in_db(username, message)
    
    return redirect('/')

if __name__ == '__main__':
    init_db()
    
    print("Test Case 1: Insert message from user1")
    insert_user_message_in_db("user1", "Hello World!")
    
    print("Test Case 2: Insert message from user2")
    insert_user_message_in_db("user2", "This is a test message")
    
    print("Test Case 3: Insert message from user3")
    insert_user_message_in_db("user3", "Python Flask example")
    
    print("Test Case 4: Insert message from user4")
    insert_user_message_in_db("user4", "Another test message")
    
    print("Test Case 5: Display all messages")
    messages = get_messages()
    for msg in messages:
        print(f"{msg[0]}: {msg[1]}")
    
    app.run(debug=True)
