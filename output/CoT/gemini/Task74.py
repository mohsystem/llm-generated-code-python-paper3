import psycopg2

# To run this code, you need the psycopg2 library.
# Install it using pip:
# pip install psycopg2-binary

def connect_to_postgres(dbname, user, password, host, port):
    """
    Establishes a connection to a PostgreSQL database.

    Args:
        dbname (str): The name of the database.
        user (str): The username for the connection.
        password (str): The password for the connection.
        host (str): The database host address.
        port (int or str): The port number.

    Returns:
        A connection object or None if the connection fails.
    
    Security Note: In a real application, credentials should be sourced securely
    (e.g., from environment variables, a secrets manager) and not hardcoded.
    Always use parameterized queries (e.g., cursor.execute("SELECT ... WHERE id = %s", (some_id,)))
    with the returned connection to prevent SQL injection.
    """
    conn = None
    try:
        conn = psycopg2.connect(
            dbname=dbname,
            user=user,
            password=password,
            host=host,
            port=port
        )
    except psycopg2.OperationalError as e:
        print(f"Operational Error: {e}")
        # In a real app, use a logger.
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        
    return conn

if __name__ == "__main__":
    # --- IMPORTANT ---
    # Replace these placeholder values with your actual PostgreSQL database details.
    # For the test cases to work as expected, you need a running PostgreSQL server.
    HOST = "localhost"
    PORT = "5432"
    DBNAME = "your_db"
    USER = "your_user"
    PASSWORD = "your_password"

    # Test Case 1: Successful Connection
    print("--- Test Case 1: Attempting a successful connection... ---")
    conn1 = connect_to_postgres(DBNAME, USER, PASSWORD, HOST, PORT)
    if conn1:
        print("Test Case 1: Connection successful!")
        conn1.close()
        print("Test Case 1: Connection closed.")
    else:
        print("Test Case 1: Connection failed. Please check your credentials and database status.")
    print()

    # Test Case 2: Incorrect Password
    print("--- Test Case 2: Attempting connection with a wrong password... ---")
    conn2 = connect_to_postgres(DBNAME, USER, "wrong_password", HOST, PORT)
    if not conn2:
        print("Test Case 2: Connection failed as expected.")
    else:
        print("Test Case 2: Connection unexpectedly succeeded.")
        conn2.close()
    print()
    
    # Test Case 3: Incorrect Database Name
    print("--- Test Case 3: Attempting connection to a non-existent database... ---")
    conn3 = connect_to_postgres("non_existent_db", USER, PASSWORD, HOST, PORT)
    if not conn3:
        print("Test Case 3: Connection failed as expected.")
    else:
        print("Test Case 3: Connection unexpectedly succeeded.")
        conn3.close()
    print()

    # Test Case 4: Incorrect User
    print("--- Test Case 4: Attempting connection with a wrong user... ---")
    conn4 = connect_to_postgres(DBNAME, "wrong_user", PASSWORD, HOST, PORT)
    if not conn4:
        print("Test Case 4: Connection failed as expected.")
    else:
        print("Test Case 4: Connection unexpectedly succeeded.")
        conn4.close()
    print()

    # Test Case 5: Incorrect Host
    print("--- Test Case 5: Attempting connection to a non-existent host... ---")
    conn5 = connect_to_postgres(DBNAME, USER, PASSWORD, "nonexistenthost", PORT)
    if not conn5:
        print("Test Case 5: Connection failed as expected.")
    else:
        print("Test Case 5: Connection unexpectedly succeeded.")
        conn5.close()
    print()