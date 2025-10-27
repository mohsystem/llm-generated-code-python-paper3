# To run this, you might need to install Flask: pip install Flask
# However, the test cases run without needing to run the web server.
from flask import Flask, jsonify
import sqlite3 # Using sqlite3 as it's a built-in module

# 1. Create a web app
app = Flask(__name__)

# --- Database Configuration Functions ---

def get_server_name():
    """Returns the server name."""
    return "localhost"

def get_database_name():
    """Returns the database name (file path for SQLite)."""
    return "mydatabase.db"

def get_database_user():
    """Returns the database user (not applicable for SQLite)."""
    return "N/A"

def get_database_password():
    """Returns the database password (not applicable for SQLite)."""
    return "N/A"

def get_database_connection():
    """Returns a database connection."""
    try:
        # Using a simple in-memory SQLite database for demonstration
        conn = sqlite3.connect(':memory:')
        return conn
    except Exception as e:
        print(f"Error connecting to database: {e}")
        return None

# --- Web App Route ---
@app.route('/db-config')
def db_config():
    """A web endpoint to display the DB configuration."""
    config = {
        "server_name": get_server_name(),
        "database_name": get_database_name(),
        "user": get_database_user(),
    }
    return jsonify(config)

# --- Main execution block with test cases ---
def run_tests():
    """Runs 5 test cases."""
    print("--- Test Case 1: Get Server Name ---")
    print(f"Server: {get_server_name()}")
    print()

    print("--- Test Case 2: Get Database Name ---")
    print(f"Database: {get_database_name()}")
    print()

    print("--- Test Case 3: Get User Credentials ---")
    print(f"User: {get_database_user()}")
    print(f"Password: {get_database_password()}")
    print()

    print("--- Test Case 4: Get Full Config Summary ---")
    print(f"Server: {get_server_name()}, DB: {get_database_name()}, User: {get_database_user()}")
    print()
    
    print("--- Test Case 5: Attempt Database Connection ---")
    connection = get_database_connection()
    if connection:
        print(f"Successfully obtained a connection object: {connection}")
        connection.close()
    else:
        print("Failed to get a connection object.")

if __name__ == '__main__':
    run_tests()
    # To run the web app, you would uncomment the following line:
    # app.run(debug=True)