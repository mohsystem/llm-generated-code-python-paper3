import sqlite3
import os
from flask import Flask, jsonify

# Note: This code requires the Flask library.
# You can install it using pip:
# pip install Flask

DB_FILE = "webapp.db"
app = Flask(__name__)

def setup_database():
    """Create and populate the database for the web app."""
    # Remove old database file if it exists for a clean run
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            is_moderator BOOLEAN NOT NULL CHECK (is_moderator IN (0, 1))
        )
    ''')
    users_data = [
        (1, 'alice', True),
        (2, 'bob', False),
        (3, 'charlie', True),
        (4, 'diana', False),
        (5, 'eve', False)
    ]
    cursor.executemany('INSERT INTO users VALUES (?, ?, ?)', users_data)
    conn.commit()
    conn.close()

def is_user_moderator(user_id):
    """
    Connects to the database and executes a query to check if the user is a moderator.
    Returns: True if moderator, False if not, None if user not found.
    """
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('SELECT is_moderator FROM users WHERE id = ?', (user_id,))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return bool(result[0])
        else:
            return None
    except sqlite3.Error:
        return None

@app.route("/is_moderator/<int:user_id>")
def check_moderator_route(user_id):
    """Define a route for the app that will be called when the URL is accessed."""
    is_mod = is_user_moderator(user_id)
    if is_mod is None:
        return jsonify({"error": "User not found"}), 404
    else:
        # Return the result of the query as JSON
        return jsonify({"user_id": user_id, "is_moderator": is_mod})

class Lse138:
    @staticmethod
    def main():
        """Main method to run test cases."""
        print("--- Running 5 Test Cases ---")
        
        # Ensure the database is set up for testing
        setup_database()
        
        test_cases = [1, 2, 5, 3, 99] # 5 User IDs to test
        for i, user_id in enumerate(test_cases, 1):
            result = is_user_moderator(user_id)
            print(f"Test Case {i}: Checking user_id = {user_id}")
            if result is None:
                print("Result: User not found.")
            else:
                print(f"Result: Is moderator? {result}")
            print("----------------------------")

if __name__ == '__main__':
    # Run the 5 test cases defined in the Lse138 class
    Lse138.main()

    # After running tests, start the Flask web server
    print("\n--- Starting Web Server on http://127.0.0.1:5000 ---")
    print("Try accessing: http://127.0.0.1:5000/is_moderator/1")
    print("Or: http://127.0.0.1:5000/is_moderator/2")
    # The app.run() command will start the server and block execution.
    # Use Ctrl+C to stop the server.
    app.run(debug=False)