import sqlite3
import os
from flask import Flask, jsonify, request

# --- Database Setup ---
DATABASE_FILE = "webapp_users.db"

def setup_database():
    """Initializes the database, creates the table, and inserts sample data."""
    # Delete the old database file if it exists, for a clean start
    if os.path.exists(DATABASE_FILE):
        os.remove(DATABASE_FILE)
        
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    
    print("Setting up the database...")
    # Create users table
    cursor.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            is_moderator BOOLEAN NOT NULL
        )
    """)
    
    # Insert sample data
    sample_users = [
        (1, 'Alice', True),
        (2, 'Bob', False),
        (3, 'Charlie', True),
        (4, 'David', False)
    ]
    cursor.executemany("INSERT INTO users (id, username, is_moderator) VALUES (?, ?, ?)", sample_users)
    
    conn.commit()
    conn.close()
    print("Database setup complete.")

# --- Core Logic ---
def is_user_moderator(user_id):
    """
    Checks if a user is a moderator.
    Uses parameterized queries to prevent SQL injection.

    Args:
        user_id (int): The ID of the user to check.

    Returns:
        bool: True if the user is a moderator, False otherwise.
    """
    is_moderator = False
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        
        # Use a parameterized query to prevent SQL injection.
        # The '?' is a placeholder for the user_id.
        query = "SELECT is_moderator FROM users WHERE id = ?"
        
        # The second argument to execute must be a tuple.
        cursor.execute(query, (user_id,))
        
        result = cursor.fetchone() # Fetches one row
        if result:
            # result[0] will be 1 for True, 0 for False in SQLite
            is_moderator = bool(result[0])
            
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        # In a real app, you would have more robust error logging.
        # Re-raise or return an error state if needed.
    finally:
        if conn:
            conn.close()
            
    return is_moderator

# --- Web App Setup ---
app = Flask(__name__)

@app.route('/isModerator', methods=['GET'])
def check_moderator_status():
    """
    Web endpoint to check moderator status.
    Expects a 'userId' query parameter.
    """
    user_id_str = request.args.get('userId')
    
    if not user_id_str:
        return jsonify({"error": "userId parameter is missing"}), 400
        
    try:
        user_id = int(user_id_str)
    except ValueError:
        return jsonify({"error": "Invalid userId format. Must be an integer."}), 400
        
    # Call the core logic function
    try:
        is_mod = is_user_moderator(user_id)
        return jsonify({"userId": user_id, "isModerator": is_mod})
    except Exception as e:
        # Generic error for any unexpected issues during the check
        print(f"An unexpected error occurred: {e}")
        return jsonify({"error": "An internal error occurred."}), 500


# --- Main Execution ---
def run_tests():
    """Runs test cases against the core logic function."""
    print("\n--- Running Test Cases ---")
    test_cases = {
        1: True,   # Moderator user
        2: False,  # Non-moderator user
        3: True,   # Another moderator user
        4: False,  # Another non-moderator user
        99: False  # Non-existent user
    }
    
    for user_id, expected in test_cases.items():
        actual = is_user_moderator(user_id)
        status = "PASS" if actual == expected else "FAIL"
        print(f"Test for userId={user_id}: Expected={expected}, Actual={actual} -> {status}")
    print("--- Test Cases Finished ---\n")

if __name__ == '__main__':
    # 1. Setup the database
    setup_database()
    
    # 2. Run test cases
    run_tests()
    
    # 3. Start the Flask web server
    print("Starting Flask server on http://127.0.0.1:5000")
    print("Try accessing http://127.0.0.1:5000/isModerator?userId=1")
    print("Try accessing http://127.0.0.1:5000/isModerator?userId=2")
    app.run(debug=True)