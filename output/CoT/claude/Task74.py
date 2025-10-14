
import psycopg2
from psycopg2 import sql, OperationalError
import sys

def create_postgres_connection(host, port, database, username, password, use_ssl=False):
    """\n    Creates and returns a secure PostgreSQL database connection\n    \n    Args:\n        host (str): Database host\n        port (int): Database port\n        database (str): Database name\n        username (str): Database username\n        password (str): Database password\n        use_ssl (bool): Whether to use SSL connection\n        \n    Returns:\n        connection: PostgreSQL connection object\n        \n    Raises:\n        ValueError: If input parameters are invalid\n        psycopg2.Error: If connection fails\n    """
    # Validate input parameters
    if not host or not isinstance(host, str) or not host.strip():
        raise ValueError("Host cannot be null or empty")
    
    if not database or not isinstance(database, str) or not database.strip():
        raise ValueError("Database name cannot be null or empty")
    
    if not username or not isinstance(username, str) or not username.strip():
        raise ValueError("Username cannot be null or empty")
    
    if password is None or not isinstance(password, str):
        raise ValueError("Password cannot be null")
    
    if not isinstance(port, int) or port < 1 or port > 65535:
        raise ValueError("Port must be between 1 and 65535")
    
    try:
        # Build connection parameters
        conn_params = {
            'host': host,
            'port': port,
            'database': database,
            'user': username,
            'password': password,
            'connect_timeout': 10
        }
        
        # Add SSL parameters if required
        if use_ssl:
            conn_params['sslmode'] = 'require'
        
        # Create and return connection
        connection = psycopg2.connect(**conn_params)
        
        return connection
        
    except OperationalError as e:
        raise psycopg2.Error(f"Failed to connect to PostgreSQL: {str(e)}")


def test_connection(test_name, host, port, database, username, password, use_ssl):
    """Helper function to test connection creation"""
    print(f"{test_name}")
    try:
        conn = create_postgres_connection(host, port, database, username, password, use_ssl)
        print("✓ Connection created successfully")
        if conn and not conn.closed:
            conn.close()
            print("✓ Connection closed successfully")
    except ValueError as e:
        print(f"✗ Validation Error: {e}")
    except Exception as e:
        print(f"✗ Error: {e}")
    print()


if __name__ == "__main__":
    print("=== PostgreSQL Connection Test Cases ===\\n")
    
    # Test Case 1: Standard connection (simulated)
    test_connection("Test 1: Standard Connection",
                   "localhost", 5432, "testdb", "postgres", "password", False)
    
    # Test Case 2: SSL Connection
    test_connection("Test 2: SSL Connection",
                   "localhost", 5432, "testdb", "postgres", "password", True)
    
    # Test Case 3: Invalid port
    test_connection("Test 3: Invalid Port",
                   "localhost", -1, "testdb", "postgres", "password", False)
    
    # Test Case 4: Empty host
    test_connection("Test 4: Empty Host",
                   "", 5432, "testdb", "postgres", "password", False)
    
    # Test Case 5: None database
    test_connection("Test 5: None Database",
                   "localhost", 5432, None, "postgres", "password", False)
