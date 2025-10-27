import sqlite3
from flask import Flask, request, jsonify

# Note: This code requires the Flask library.
# Install it using: pip install Flask

app = Flask(__name__)
DB_NAME = "user_moderators.db"

def setup_database():
    """Sets up the database and populates it with initial data."""
    conn = None
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        # Drop table if it exists to start fresh
        cursor.execute("DROP TABLE IF EXISTS users")
        
        # Create a users table
        cursor.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                is_moderator BOOLEAN NOT NULL CHECK (is_moderator IN (0, 1))
            )
        """)
        
        # Insert sample data
        users = [
            (1, 'alice', 1),   # Moderator
            (2, 'bob', 0),     # Not a moderator
            (3, 'charlie', 0)  # Not a moderator
        ]
        cursor.executemany("INSERT INTO users (id, username, is_moderator) VALUES (?, ?, ?)", users)
        
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database setup failed: {e}")
    finally:
        if conn:
            conn.close()

def is_user_moderator(user_id):
    """
    Securely checks if a user is a moderator using parameterized queries.
    
    Args:
        user_id (str): The ID of the user to check.
        
    Returns:
        bool: True if the user is a moderator, False otherwise.
    """
    is_moderator = False
    conn = None
    
    # Input validation
    if not user_id or not user_id.isdigit():
        print(f"Invalid userId format: {user_id}")
        return False

    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        # The query uses a placeholder (?) to prevent SQL injection
        query = "SELECT is_moderator FROM users WHERE id = ?"
        
        # Execute with the user_id as a parameter
        cursor.execute(query, (user_id,))
        
        result = cursor.fetchone()
        
        if result:
            is_moderator = bool(result[0])
            
    except sqlite3.Error as e:
        print(f"Query failed: {e}")
    finally:
        if conn:
            conn.close()
            
    return is_moderator

@app.route('/is_moderator', methods=['GET'])
def check_moderator_status():
    """Flask route to check moderator status."""
    user_id = request.args.get('userId')
    
    if not user_id:
        return jsonify({"error": "userId parameter is required"}), 400
        
    is_mod = is_user_moderator(user_id)
    
    return jsonify({"userId": user_id, "isModerator": is_mod})

def run_tests():
    """Runs 5 test cases against the core logic."""
    print("--- Running 5 Test Cases ---")
    # Test Case 1: User is a moderator
    assert is_user_moderator("1") is True
    print("Test 1 (User 1 is Moderator): Passed")
    # Test Case 2: User is not a moderator
    assert is_user_moderator("2") is False
    print("Test 2 (User 2 is Not Moderator): Passed")
    # Test Case 3: User does not exist
    assert is_user_moderator("99") is False
    print("Test 3 (User 99 does not exist): Passed")
    # Test Case 4: Invalid input (non-numeric)
    assert is_user_moderator("abc") is False
    print("Test 4 (Invalid input 'abc'): Passed")
    # Test Case 5: Invalid input (SQL injection attempt)
    assert is_user_moderator("1 OR 1=1") is False
    print("Test 5 (SQLi attempt '1 OR 1=1'): Passed")
    print("--- Test Cases Finished ---\n")

if __name__ == '__main__':
    # 1. Set up the database
    setup_database()
    
    # 2. Run test cases on the core logic
    run_tests()
    
    # 3. Set up and start the web server
    print("Starting Flask server on port 5000.")
    print("Try visiting http://localhost:5000/is_moderator?userId=1")
    app.run(port=5000, debug=False)