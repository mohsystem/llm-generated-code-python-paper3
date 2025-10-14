import psycopg2

def get_postgres_connection(host, port, dbname, user, password):
    """
    Creates and returns a connection object for a Postgres database.
    Requires the 'psycopg2-binary' library to be installed (pip install psycopg2-binary).
    For security, this function attempts to connect using SSL.
    
    Args:
        host (str): The database server host.
        port (str or int): The database server port.
        dbname (str): The name of the database.
        user (str): The username for authentication.
        password (str): The password for authentication.
        
    Returns:
        A connection object or None if the connection fails.
    """
    conn = None
    try:
        # Secure connection with sslmode set to 'require'.
        # For self-signed certificates, you might need additional options
        # like sslcert, sslkey, sslrootcert.
        conn = psycopg2.connect(
            host=host,
            port=port,
            dbname=dbname,
            user=user,
            password=password,
            sslmode='require'
        )
        print(f"Connection to {dbname} established successfully.")
    except psycopg2.Error as e:
        print(f"Error: Unable to connect to the database.")
        print(f"Details: {e}")
    
    return conn

if __name__ == '__main__':
    # --- Test Cases ---
    # These are placeholder credentials and will likely fail to connect.
    # Replace with your actual database details to test a successful connection.

    # Test Case 1: Valid-looking but likely incorrect credentials
    print("--- Test Case 1 ---")
    conn1 = get_postgres_connection("localhost", "5432", "mydatabase", "myuser", "mypassword")
    if conn1:
        print("Test Case 1: Connection object returned.")
        conn1.close()
    else:
        print("Test Case 1: Failed to get connection object.")
    print()

    # Test Case 2: Invalid host
    print("--- Test Case 2 ---")
    conn2 = get_postgres_connection("invalid-host", "5432", "testdb", "user2", "pass2")
    if conn2:
        print("Test Case 2: Connection object returned.")
        conn2.close()
    else:
        print("Test Case 2: Failed to get connection object.")
    print()

    # Test Case 3: Invalid port
    print("--- Test Case 3 ---")
    conn3 = get_postgres_connection("localhost", "9999", "proddb", "user3", "pass3")
    if conn3:
        print("Test Case 3: Connection object returned.")
        conn3.close()
    else:
        print("Test Case 3: Failed to get connection object.")
    print()
    
    # Test Case 4: Null password (using None)
    print("--- Test Case 4 ---")
    conn4 = get_postgres_connection("localhost", "5432", "analytics", "user4", None)
    if conn4:
        print("Test Case 4: Connection object returned.")
        conn4.close()
    else:
        print("Test Case 4: Failed to get connection object.")
    print()
    
    # Test Case 5: Empty parameters
    print("--- Test Case 5 ---")
    conn5 = get_postgres_connection("", "", "", "", "")
    if conn5:
        print("Test Case 5: Connection object returned.")
        conn5.close()
    else:
        print("Test Case 5: Failed to get connection object.")
    print()