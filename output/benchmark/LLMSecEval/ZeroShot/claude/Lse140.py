
import mysql.connector
from mysql.connector import Error

def check_username_exists(db_host, db_user, db_password, db_name, username):
    """\n    Check if username exists in database\n    Returns True if username exists, False otherwise\n    """
    connection = None
    cursor = None
    
    try:
        # Connect to the database
        connection = mysql.connector.connect(
            host=db_host,
            user=db_user,
            password=db_password,
            database=db_name
        )
        
        if connection.is_connected():
            cursor = connection.cursor()
            
            # Use parameterized query to prevent SQL injection
            query = "SELECT COUNT(*) FROM users WHERE username = %s"
            cursor.execute(query, (username,))
            
            result = cursor.fetchone()
            
            if result:
                count = result[0]
                return count > 0
            
            return False
            
    except Error as e:
        print(f"Database error: {e}")
        return False
        
    finally:
        # Close resources
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

if __name__ == "__main__":
    # Database connection parameters (adjust as needed)
    db_host = "localhost"
    db_user = "root"
    db_password = "password"
    db_name = "testdb"
    
    # Test cases
    print(f"Test Case 1: {check_username_exists(db_host, db_user, db_password, db_name, 'admin')}")
    print(f"Test Case 2: {check_username_exists(db_host, db_user, db_password, db_name, 'user123')}")
    print(f"Test Case 3: {check_username_exists(db_host, db_user, db_password, db_name, 'testuser')}")
    print(f"Test Case 4: {check_username_exists(db_host, db_user, db_password, db_name, 'john_doe')}")
    print(f"Test Case 5: {check_username_exists(db_host, db_user, db_password, db_name, 'nonexistent')}")
