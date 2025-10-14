import sqlite3
import re
import os
from flask import Flask, request, jsonify

# DEPENDENCIES:
# pip install Flask
#
# USAGE:
# 1. Save the code as a Python file (e.g., app.py).
# 2. Run from the terminal: python app.py
# 3. The server will start on http://127.0.0.1:5000

DB_FILE = "user_database.db"

app = Flask(__name__)

# --- Secure Configuration ---
# In a real app, use environment variables or a config file for secret keys
app.config['SECRET_KEY'] = os.urandom(24)

# --- Database Setup ---
def init_db():
    """Initializes the database and creates the users table if it doesn't exist."""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        ''')
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        exit(1)

# --- API Endpoint ---
@app.route('/users', methods=['POST'])
def create_user():
    """
    API endpoint to create a new user.
    Accepts a JSON payload with 'username' and 'email'.
    """
    # 1. Input Parsing and Basic Validation
    if not request.is_json:
        return jsonify({"error": "Bad Request: Invalid JSON"}), 400
    
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')

    # 2. Detailed Input Validation
    if not username or not isinstance(username, str) or not email or not isinstance(email, str):
        return jsonify({"error": "Bad Request: 'username' and 'email' are required and must be strings"}), 400

    if len(username) > 50 or len(email) > 254:
        return jsonify({"error": "Bad Request: Input length exceeds maximum limit"}), 400

    # A simple regex for email validation
    if not re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email):
        return jsonify({"error": "Bad Request: Invalid email format"}), 400

    # 3. Database Interaction
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # --- Parameterized Query to prevent SQL Injection ---
        sql = "INSERT INTO users (username, email) VALUES (?, ?)"
        cursor.execute(sql, (username.strip(), email.strip()))
        
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        
        return jsonify({
            "message": "User created successfully",
            "user_id": user_id
        }), 201

    except sqlite3.IntegrityError:
        # This error occurs if the UNIQUE constraint on username or email fails
        return jsonify({"error": "Conflict: Username or email already exists"}), 409
    except sqlite3.Error as e:
        # Generic database error
        app.logger.error(f"Database error: {e}")
        return jsonify({"error": "Internal Server Error"}), 500

if __name__ == '__main__':
    init_db()
    print("Server starting on http://127.0.0.1:5000")
    print("API Endpoint: POST /users")
    print("--- 5 Test Cases (use a tool like curl) ---")
    print("1. Successful creation:")
    print("   curl -X POST -H \"Content-Type: application/json\" -d '{\"username\":\"alice\",\"email\":\"alice@example.com\"}' http://127.0.0.1:5000/users")
    print("\n2. Duplicate username (409 Conflict):")
    print("   curl -X POST -H \"Content-Type: application/json\" -d '{\"username\":\"alice\",\"email\":\"alice2@example.com\"}' http://127.0.0.1:5000/users")
    print("\n3. Duplicate email (409 Conflict):")
    print("   curl -X POST -H \"Content-Type: application/json\" -d '{\"username\":\"alice2\",\"email\":\"alice@example.com\"}' http://127.0.0.1:5000/users")
    print("\n4. Missing data (400 Bad Request):")
    print("   curl -X POST -H \"Content-Type: application/json\" -d '{\"username\":\"bob\"}' http://127.0.0.1:5000/users")
    print("\n5. Malformed JSON (400 Bad Request):")
    print("   curl -X POST -H \"Content-Type: application/json\" -d '{\"username\":\"carol\",\"email\":\"carol@example.com\"' http://127.0.0.1:5000/users")
    app.run(debug=False) # debug=False is important for production