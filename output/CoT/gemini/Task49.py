# To run this code, you first need to install the Flask library:
# pip install Flask

import sqlite3
import json
import re
from flask import Flask, request, jsonify

DB_FILE = 'users_py.db'

# 1. Database setup function
def init_db():
    """Initializes the database and creates the users table if it doesn't exist."""
    # The 'with' statement ensures the connection is closed automatically.
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE
            )
        ''')
        conn.commit()

# 2. Core logic for adding a user with validation and security
def add_user_logic(name, email):
    """Handles the business logic of validating and adding a user to the database."""
    # --- Input Validation ---
    if not name or not isinstance(name, str) or not (0 < len(name) <= 100):
        return {"error": "Invalid name provided. Must be a string between 1 and 100 characters."}, 400
    if not email or not isinstance(email, str) or len(email) > 100 or not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return {"error": "Invalid email provided."}, 400

    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        # --- Secure Database Operation ---
        # Use a parameterized query (with '?') to prevent SQL injection.
        cursor.execute("INSERT INTO users (name, email) VALUES (?, ?)", (name, email))
        conn.commit()
        user_id = cursor.lastrowid
        return {"message": f"User '{name}' created successfully.", "id": user_id}, 201
    except sqlite3.IntegrityError:  # This error is raised for UNIQUE constraint violations
        return {"error": f"Email '{email}' already exists."}, 409 # Conflict
    except sqlite3.Error as e:
        # Log the internal error but don't expose it to the client
        print(f"Database error: {e}")
        return {"error": "An internal server error occurred."}, 500
    finally:
        if conn:
            conn.close()

# 3. Flask application and API endpoint
app = Flask(__name__)

@app.route('/api/users', methods=['POST'])
def create_user_endpoint():
    """API endpoint to receive user data and store it."""
    if not request.is_json:
        return jsonify({"error": "Request must be in JSON format"}), 415 # Unsupported Media Type

    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided or invalid JSON"}), 400 # Bad Request
        
    name = data.get('name')
    email = data.get('email')
    
    response_data, status_code = add_user_logic(name, email)
    return jsonify(response_data), status_code

# 4. Main execution block with test cases
def run_tests():
    """Runs a series of tests against the add_user_logic function."""
    print("--- Running Logical Test Cases ---")
    
    # Test Case 1: Valid user data
    print("\nTest 1: Add a valid user 'Bob'")
    resp, code = add_user_logic("Bob", "bob.test@example.com")
    print(f"Response: {resp}, Status: {code}")

    # Test Case 2: Duplicate email
    print("\nTest 2: Add a user with a duplicate email")
    resp, code = add_user_logic("Bob Smith", "bob.test@example.com")
    print(f"Response: {resp}, Status: {code}")

    # Test Case 3: Invalid email format
    print("\nTest 3: Add a user with an invalid email")
    resp, code = add_user_logic("Charlie", "charlie-is-not-an-email")
    print(f"Response: {resp}, Status: {code}")

    # Test Case 4: Missing name (None)
    print("\nTest 4: Add a user with a missing name")
    resp, code = add_user_logic(None, "dave@example.com")
    print(f"Response: {resp}, Status: {code}")
    
    # Test Case 5: Empty email string
    print("\nTest 5: Add a user with an empty email")
    resp, code = add_user_logic("Frank", "")
    print(f"Response: {resp}, Status: {code}")
    
    print("\n--- Test Cases Finished ---")


if __name__ == '__main__':
    init_db()
    run_tests()
    
    # To run the web server, uncomment the line below.
    # The server will be accessible at http://127.0.0.1:5000
    # You can test it with a command like:
    # curl -X POST -H "Content-Type: application/json" -d '{"name":"Grace", "email":"grace@example.com"}' http://127.0.0.1:5000/api/users
    
    # print("\nStarting Flask server on http://127.0.0.1:5000")
    # app.run(host='127.0.0.1', port=5000)