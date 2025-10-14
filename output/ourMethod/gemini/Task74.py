import os
import sys

# To run this code, you need the psycopg2 library.
# Install it using pip: pip install psycopg2-binary
#
# Before running, set the following environment variables:
# export PG_HOST="localhost"
# export PG_PORT="5432"
# export PG_DBNAME="testdb"
# export PG_USER="testuser"
# export PG_PASSWORD="testpassword"

try:
    import psycopg2
except ImportError:
    print("Error: psycopg2 library not found. Please install it using 'pip install psycopg2-binary'", file=sys.stderr)
    sys.exit(1)

def get_connection(host, port, dbname, user, password):
    """
    Creates and returns a connection object for a PostgreSQL database.
    
    Args:
        host (str): The database server host.
        port (str): The database server port.
        dbname (str): The name of the database.
        user (str): The username for authentication.
        password (str): The password for authentication.
        
    Returns:
        psycopg2.connection: A connection object or None if connection fails.
    """
    # Rule #13: Avoid hardcoding credentials. The credentials are passed as parameters.
    if not all([host, port, dbname, user, password]):
        print("Error: All connection parameters must be provided.", file=sys.stderr)
        return None

    try:
        # Rule #4, #5: Enforce SSL usage through connection parameters.
        conn = psycopg2.connect(
            host=host,
            port=port,
            dbname=dbname,
            user=user,
            password=password,
            sslmode='require'  
        )
        print(f"Connection to {dbname} established successfully.")
        return conn
    except psycopg2.Error as e:
        # Rule #14: Handle exceptions gracefully without leaking sensitive info.
        print(f"Connection Failed: {e}", file=sys.stderr)
        return None

def main():
    """Main function to run test cases."""
    print("--- Running Test Cases ---")

    # Test Case 1: Successful connection using environment variables
    print("\n[Test Case 1: Successful Connection]")
    # Rule #12: Use environment variables to manage sensitive credentials
    db_host = os.environ.get("PG_HOST")
    db_port = os.environ.get("PG_PORT")
    db_name = os.environ.get("PG_DBNAME")
    db_user = os.environ.get("PG_USER")
    db_password = os.environ.get("PG_PASSWORD")

    # Rule #16: Check that environment variables are set
    if not all([db_host, db_port, db_name, db_user, db_password]):
        print("Skipping Test Case 1: Please set PG_HOST, PG_PORT, PG_DBNAME, PG_USER, and PG_PASSWORD environment variables.")
    else:
        conn = None
        try:
            # Using 'with' statement ensures the connection is closed automatically
            with get_connection(db_host, db_port, db_name, db_user, db_password) as conn:
                if conn:
                    print("Connection object is valid.")
                else:
                    print("Failed to get connection object.")
        except (AttributeError, psycopg2.Error): # Catch error if get_connection returns None or connection fails
            print("Connection context failed as expected or an error occurred.")
            
    # Test Case 2: Connection with a wrong password
    print("\n[Test Case 2: Wrong Password]")
    if db_host:
        with get_connection(db_host, db_port, db_name, db_user, "wrongpassword") as conn:
            pass # context manager handles None return
    else:
        print("Skipping Test Case 2: Environment variables not set.")

    # Test Case 3: Connection to a non-existent database
    print("\n[Test Case 3: Non-existent Database]")
    if db_host:
        with get_connection(db_host, db_port, "nonexistentdb", db_user, db_password) as conn:
            pass
    else:
        print("Skipping Test Case 3: Environment variables not set.")

    # Test Case 4: Connection to a wrong host
    print("\n[Test Case 4: Wrong Host]")
    if db_host:
        with get_connection("127.0.0.99", db_port, db_name, db_user, db_password) as conn:
            pass
    else:
        print("Skipping Test Case 4: Environment variables not set.")

    # Test Case 5: Connection with a missing user
    print("\n[Test Case 5: Missing User]")
    if db_host:
        with get_connection(db_host, db_port, db_name, "", db_password) as conn:
            pass
    else:
        print("Skipping Test Case 5: Environment variables not set.")

if __name__ == "__main__":
    main()