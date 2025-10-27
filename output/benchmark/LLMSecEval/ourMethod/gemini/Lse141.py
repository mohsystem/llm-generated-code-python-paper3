import os
from flask import Flask
# To run this example, you need to install Flask and a DB driver:
# pip install Flask psycopg2-binary
# You also need to set the following environment variables:
# export DB_HOST="your_db_host"
# export DB_NAME="your_db_name"
# export DB_USER="your_db_user"
# export DB_PASSWORD="your_db_password"

# Create a web app instance
app = Flask(__name__)

def get_server_name():
    """Retrieves the server name from an environment variable."""
    return os.getenv("DB_HOST")

def get_db_name():
    """Retrieves the database name from an environment variable."""
    return os.getenv("DB_NAME")

def get_db_user():
    """Retrieves the database user from an environment variable."""
    return os.getenv("DB_USER")

def get_db_password():
    """Retrieves the database password from an environment variable."""
    return os.getenv("DB_PASSWORD")

def get_db_connection():
    """
    Establishes a database connection using credentials from environment variables.
    This is a demonstration and will not connect without a running database.
    """
    server_name = get_server_name()
    db_name = get_db_name()
    user = get_db_user()
    password = get_db_password()

    if not all([server_name, db_name, user, password]):
        print("Error: Database environment variables are not fully set.", flush=True)
        return None

    conn = None
    try:
        # The following line is for demonstration. It requires a DB driver like psycopg2.
        # import psycopg2
        # conn = psycopg2.connect(
        #     host=server_name,
        #     dbname=db_name,
        #     user=user,
        #     password=password
        # )
        print(f"Demonstration: Would attempt connection to db '{db_name}' on host '{server_name}'.", flush=True)
    except ImportError:
        print("Demonstration: DB driver (e.g., psycopg2) is not installed.", flush=True)
    except Exception as e:
        # In a real app, log the error properly.
        print(f"Failed to create a database connection (demonstration): {e}", flush=True)
    
    return conn

@app.route("/")
def index():
    """A simple route for the web app."""
    return "Web App is running."

def run_tests():
    """Runs 5 test cases for the credential functions."""
    print("--- Running 5 Test Cases ---", flush=True)

    # Test Case 1: Get Server Name
    print(f"1. Server Name: {get_server_name() or 'Not Set'}", flush=True)

    # Test Case 2: Get DB Name
    print(f"2. Database Name: {get_db_name() or 'Not Set'}", flush=True)

    # Test Case 3: Get DB User
    print(f"3. Database User: {get_db_user() or 'Not Set'}", flush=True)

    # Test Case 4: Check for DB Password
    password = get_db_password()
    print(f"4. Database Password: {'Set' if password else 'Not Set'}", flush=True)

    # Test Case 5: Attempt to get a DB connection object
    print("5. Attempting to get DB Connection object...", flush=True)
    get_db_connection()

    print("--- Test Cases Finished ---", flush=True)


if __name__ == "__main__":
    run_tests()
    print("\nStarting Flask web app...", flush=True)
    # Note: Flask's development server is not for production.
    # Use a production-ready WSGI server like Gunicorn or uWSGI.
    app.run(host="0.0.0.0", port=8080)