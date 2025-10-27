import sqlite3
import os
from flask import Flask, request, jsonify

# Note: This example requires the Flask library.
# Install it with: pip install Flask

app = Flask(__name__)
DB_NAME = "user_database.db"

def setup_database(db_name):
    """Initializes the database for the application."""
    # Rule #7: Avoid hardcoding credentials. db_name is a parameter, but in a real app
    # this would come from a secure config (e.g., environment variable).
    if os.path.exists(db_name):
        os.remove(db_name)
        
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    
    # Create table
    cursor.execute('''
    CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL,
        is_moderator INTEGER NOT NULL
    )
    ''')
    
    # Insert some data
    users_to_add = [
        (1, 'Alice', 1),  # Alice is a moderator
        (2, 'Bob', 0)      # Bob is not a moderator
    ]
    cursor.executemany('INSERT INTO users VALUES (?, ?, ?)', users_to_add)
    
    conn.commit()
    conn.close()
    print(f"Database '{db_name}' initialized successfully.")


def query_is_moderator(user_id):
    """
    Checks if a user is a moderator.
    Returns a boolean or None if user not found.
    """
    conn = None
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        # Rule #2: Use parameterized queries to prevent SQL Injection (CWE-89)
        cursor.execute("SELECT is_moderator FROM users WHERE id = ?", (user_id,))
        
        result = cursor.fetchone()
        
        if result:
            return result[0] == 1
        else:
            return None
    except sqlite3.Error as e:
        # In a real app, log this error securely.
        print(f"Database error: {e}")
        raise # Re-raise to be handled by the route
    finally:
        if conn:
            conn.close()

@app.route('/is_moderator', methods=['GET'])
def is_moderator_route():
    """Web route to check if a user is a moderator."""
    user_id_str = request.args.get('user_id')

    if not user_id_str:
        return jsonify({"error": "user_id parameter is required"}), 400

    # Rule #1: Ensure all input is validated and sanitized.
    try:
        user_id = int(user_id_str)
    except ValueError:
        return jsonify({"error": "Invalid user_id format, must be an integer"}), 400
        
    try:
        is_mod = query_is_moderator(user_id)
        
        if is_mod is None:
            return jsonify({"error": f"User with id {user_id} not found"}), 404
        
        return jsonify({"user_id": user_id, "is_moderator": is_mod}), 200
    except Exception:
        # Rule #10: Do not leak internal details in error messages.
        return jsonify({"error": "Internal server error"}), 500


if __name__ == '__main__':
    setup_database(DB_NAME)
    print("\n--- Test Cases ---")
    print("1. Moderator user: curl \"http://127.0.0.1:5000/is_moderator?user_id=1\"")
    print("2. Non-moderator user: curl \"http://127.0.0.1:5000/is_moderator?user_id=2\"")
    print("3. Non-existent user: curl \"http://127.0.0.1:5000/is_moderator?user_id=99\"")
    print("4. Invalid input: curl \"http://127.0.0.1:5000/is_moderator?user_id=abc\"")
    print("5. Missing input: curl \"http://127.0.0.1:5000/is_moderator\"")
    
    # For production, use a proper WSGI server instead of app.run()
    app.run(debug=False)