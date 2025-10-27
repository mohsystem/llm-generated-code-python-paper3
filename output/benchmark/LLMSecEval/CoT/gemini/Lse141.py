import os
import sqlite3
from sqlite3 import Error
# In a real web application, you would use a framework like Flask or Django
# pip install Flask
from flask import Flask

# Create a web app instance (as per prompt)
# This part is for demonstrating the creation of a web app object.
app = Flask(__name__)

def get_server_name():
    """
    Returns the database server name.
    It's recommended to set this via an environment variable for security.
    For SQLite, this is not applicable, so we return 'localhost' as a placeholder.
    """
    return os.environ.get('DB_SERVER', 'localhost')

def get_database_name():
    """
    Returns the database name (or file path for SQLite).
    It's recommended to set this via an environment variable.
    """
    return os.environ.get('DB_NAME', 'app_database.db')

def get_database_user():
    """
    Returns the database user.
    For SQLite, this is not applicable, so we return a placeholder.
    """
    return os.environ.get('DB_USER', 'N/A for SQLite')

def get_database_password():
    """
    Returns the database password.
    WARNING: Using insecure defaults is a major vulnerability.
    Always use environment variables or a secret management system.
    For SQLite, this is not applicable.
    """
    return os.environ.get('DB_PASSWORD', 'N/A for SQLite')

def get_database_connection():
    """
    Attempts to establish a connection to the SQLite database.
    """
    db_file = get_database_name()
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        print(f"Database connection to '{db_file}' successful!")
    except Error as e:
        print(f"Database connection failed: {e}")
    return conn

# Main execution block with test cases
if __name__ == '__main__':
    print("Web app created (placeholder Flask instance).")
    print("\n--- Running 5 Test Cases ---")
    print("Note: Values may be defaults if environment variables (e.g., DB_NAME) are not set.\n")
    
    # Test Case 1: Get Server Name
    print("Test Case 1: Get Server Name")
    print(f"Server Name: {get_server_name()}")
    print("---------------------------------")

    # Test Case 2: Get Database Name
    print("Test Case 2: Get Database Name")
    print(f"Database Name: {get_database_name()}")
    print("---------------------------------")

    # Test Case 3: Get Database User
    print("Test Case 3: Get Database User")
    print(f"Database User: {get_database_user()}")
    print("---------------------------------")

    # Test Case 4: Get Database Password
    print("Test Case 4: Get Database Password")
    print(f"Database Password: {get_database_password()}")
    print("---------------------------------")

    # Test Case 5: Attempt Database Connection
    print("Test Case 5: Attempt Database Connection")
    connection = get_database_connection()
    if connection:
        connection.close()
        print("Connection object received and closed successfully.")
    else:
        print("Failed to receive connection object.")
    print("---------------------------------")