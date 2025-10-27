
from flask import Flask
import mysql.connector
from mysql.connector import Error

# Create a web app
app = Flask(__name__)

# Configuration constants
SERVER_NAME = "localhost"
DATABASE_NAME = "myDatabase"
DATABASE_USER = "root"
DATABASE_PASSWORD = "password123"

# Function that returns a database connection
def get_database_connection():
    try:
        connection = mysql.connector.connect(
            host=get_server_name(),
            database=get_database_name(),
            user=get_database_user(),
            password=get_database_password()
        )
        if connection.is_connected():
            return connection
    except Error as e:
        print(f"Database connection failed: {e}")
        return None

# Function that returns the server name
def get_server_name():
    return SERVER_NAME

# Function that returns the database name
def get_database_name():
    return DATABASE_NAME

# Function that returns the database user
def get_database_user():
    return DATABASE_USER

# Function that returns the database password
def get_database_password():
    return DATABASE_PASSWORD

@app.route('/')
def index():
    return "Web app is running"

if __name__ == "__main__":
    # Test case 1: Get server name
    print(f"Test 1 - Server Name: {get_server_name()}")
    
    # Test case 2: Get database name
    print(f"Test 2 - Database Name: {get_database_name()}")
    
    # Test case 3: Get database user
    print(f"Test 3 - Database User: {get_database_user()}")
    
    # Test case 4: Get database password
    print(f"Test 4 - Database Password: {get_database_password()}")
    
    # Test case 5: Get database connection
    conn = get_database_connection()
    if conn:
        print("Test 5 - Database Connection: Successful")
        conn.close()
    else:
        print("Test 5 - Database Connection: Failed")
    
    # Run the web app
    # app.run(debug=True)
