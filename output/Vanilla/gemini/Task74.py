import psycopg2

def create_connection(host, port, dbname, user, password):
    """
    Creates and returns a connection object for a Postgres database.
    Note: You need to install the psycopg2 library:
    pip install psycopg2-binary
    
    Args:
        host (str): The database server host.
        port (int): The database server port.
        dbname (str): The name of the database.
        user (str): The username for authentication.
        password (str): The password for authentication.
        
    Returns:
        A connection object or None if connection fails.
    """
    try:
        conn = psycopg2.connect(
            host=host,
            port=port,
            dbname=dbname,
            user=user,
            password=password
        )
        return conn
    except psycopg2.Error as e:
        # In a real application, you would log this error.
        # print(f"Error connecting to PostgreSQL: {e}")
        return None

def run_test_case(case_num, host, port, dbname, user, password):
    """Helper function to run a single test case."""
    print(f"--- Test Case {case_num} ---")
    print(f"Attempting to connect to postgresql://{user}@{host}:{port}/{dbname}")
    conn = create_connection(host, port, dbname, user, password)
    if conn:
        print("Connection successful!")
        conn.close()
        print("Connection closed.")
    else:
        print("Connection failed.")
    print()

if __name__ == "__main__":
    # --- Test Cases ---

    # Test Case 1: Standard localhost connection (likely to fail without a running DB and correct credentials)
    run_test_case(1, "localhost", 5432, "testdb", "user", "password")
    
    # Test Case 2: Using IP address for localhost
    run_test_case(2, "127.0.0.1", 5432, "postgres", "postgres", "admin123")

    # Test Case 3: Different database and user
    run_test_case(3, "localhost", 5432, "mydatabase", "dbuser", "secret")

    # Test Case 4: Invalid host to simulate connection failure
    run_test_case(4, "nonexistent.host.com", 5432, "testdb", "user", "password")

    # Test Case 5: Invalid port
    run_test_case(5, "localhost", 9999, "testdb", "user", "password")