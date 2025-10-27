import os
from flask import Flask, jsonify

# To run this code:
# 1. pip install Flask
# 2. python your_file_name.py

# --- Web App Setup ---
app = Flask(__name__)


# --- Database Configuration Functions ---

def get_server_name():
    """
    Securely retrieves the database server name from an environment variable.
    Falls back to a default value if the environment variable is not set.
    """
    # Best practice: Store configuration in environment variables, not in code.
    return os.environ.get('DB_SERVER', 'localhost')


def get_database_name():
    """
    Securely retrieves the database name from an environment variable.
    Falls back to a default value if the environment variable is not set.
    """
    return os.environ.get('DB_NAME', 'mydatabase')


def get_database_user():
    """
    Securely retrieves the database user from an environment variable.
    Falls back to a default value if the environment variable is not set.
    """
    return os.environ.get('DB_USER', 'admin')


def get_database_password():
    """
    Securely retrieves the database password from an environment variable.
    WARNING: Avoid hardcoding passwords. This fallback is for demonstration only.
    """
    # In a real application, you might want to raise an exception if this is not set.
    return os.environ.get('DB_PASSWORD', 'INSECURE_DEFAULT_PASSWORD')


def get_db_connection():
    """
    Constructs a database connection string from configuration values.
    Note: This does not establish a real connection, it only builds the string.
    """
    # The password is intentionally redacted from the connection string
    # to prevent it from being exposed in logs or monitoring tools.
    return f"postgresql://{get_database_user()}:[REDACTED]@{get_server_name()}/{get_database_name()}"


# --- Web App Routes ---

@app.route("/config")
def show_config():
    """Web endpoint to display the database configuration."""
    config_data = {
        "server_name": get_server_name(),
        "database_name": get_database_name(),
        "user": get_database_user(),
        "password": "[REDACTED FOR SECURITY]",
        "connection_string": get_db_connection()
    }
    return jsonify(config_data)


# --- Main execution block ---

def run_tests():
    """Runs 5 test cases and prints the results."""
    print("--- Running Test Cases ---")
    print(f"1. Server Name: {get_server_name()}")
    print(f"2. Database Name: {get_database_name()}")
    print(f"3. Database User: {get_database_user()}")
    print(f"4. Database Password: {get_database_password()}")
    print(f"5. Full Connection String: {get_db_connection()}")
    print("--------------------------\n")
    print("To set these values, use environment variables like:")
    print("export DB_SERVER=db.example.com")
    print("export DB_NAME=prod_db")
    print("export DB_USER=myuser")
    print("export DB_PASSWORD='my_secret_password'\n")


if __name__ == '__main__':
    # 1. Run test cases
    run_tests()
    
    # 2. Start the web app
    print("Starting Flask web server...")
    print("Visit http://127.0.0.1:5000/config to see the configuration.")
    app.run(host='0.0.0.h', port=5000, debug=False)