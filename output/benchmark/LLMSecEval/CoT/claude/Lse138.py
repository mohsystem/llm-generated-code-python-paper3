
from flask import Flask, request, jsonify
import sqlite3
import os
from contextlib import closing

app = Flask(__name__)

DB_URL = os.getenv('DB_URL', 'test.db')
DB_USER = os.getenv('DB_USER', 'user')
DB_PASSWORD = os.getenv('DB_PASSWORD', 'password')

def check_if_moderator(username):
    if not username or not username.strip():
        return False
    
    # Use parameterized query to prevent SQL injection
    query = "SELECT is_moderator FROM users WHERE username = ?"
    
    try:
        with closing(sqlite3.connect(DB_URL)) as conn:
            with closing(conn.cursor()) as cursor:
                cursor.execute(query, (username,))
                result = cursor.fetchone()
                if result:
                    return bool(result[0])
    except sqlite3.Error as e:
        print("Database error occurred")
        return False
    
    return False

@app.route('/check-moderator', methods=['GET'])
def check_moderator_route():
    username = request.args.get('username', '')
    is_moderator = check_if_moderator(username)
    return jsonify({'is_moderator': is_moderator})

def init_test_database():
    with closing(sqlite3.connect(DB_URL)) as conn:
        with closing(conn.cursor()) as cursor:
            cursor.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, is_moderator BOOLEAN)")
            cursor.execute("DELETE FROM users")
            cursor.execute("INSERT INTO users VALUES ('admin', 1)")
            cursor.execute("INSERT INTO users VALUES ('user1', 0)")
            cursor.execute("INSERT INTO users VALUES ('moderator1', 1)")
            cursor.execute("INSERT INTO users VALUES ('user2', 0)")
            conn.commit()

if __name__ == '__main__':
    init_test_database()
    
    # Test cases
    print("Test Case 1:", check_if_moderator("admin"))  # True
    print("Test Case 2:", check_if_moderator("user1"))  # False
    print("Test Case 3:", check_if_moderator("moderator1"))  # True
    print("Test Case 4:", check_if_moderator(""))  # False
    print("Test Case 5:", check_if_moderator(None))  # False
    
    app.run(host='0.0.0.0', port=8000, debug=False)
