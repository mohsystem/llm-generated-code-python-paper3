import os
import sys
import psycopg2

# To run this code, you need the psycopg2 library.
# Install it using pip: pip install psycopg2-binary
#
# Before running, set the following environment variables:
# export DB_HOST=localhost
# export DB_PORT=5432
# export DB_NAME=yourdbname
# export DB_USER=youruser
# export DB_PASS=yourpassword
#
# And create the required table and data in your PostgreSQL database:
# CREATE TABLE users (
#     id SERIAL PRIMARY KEY,
#     username VARCHAR(50) UNIQUE NOT NULL,
#     is_moderator BOOLEAN NOT NULL DEFAULT FALSE
# );
# INSERT INTO users (username, is_moderator) VALUES ('alice', TRUE);
# INSERT INTO users (username, is_moderator) VALUES ('bob', FALSE);

def is_user_moderator(username: str) -> bool:
    """
    Checks if a user is a moderator by querying a database.
    Credentials and connection details are read from environment variables.
    Uses parameterized queries to prevent SQL injection.

    Args:
        username: The username to check.

    Returns:
        True if the user exists and is a moderator, False otherwise.
    """
    # Rule #1: Ensure all input is validated.
    if not isinstance(username, str) or not username.strip():
        print("Error: Username must be a non-empty string.", file=sys.stderr)
        return False
        
    # Rules #6, #7: Use environment variables for credentials.
    db_params = {
        "host": os.getenv("DB_HOST"),
        "port": os.getenv("DB_PORT"),
        "dbname": os.getenv("DB_NAME"),
        "user": os.getenv("DB_USER"),
        "password": os.getenv("DB_PASS")
    }

    if any(value is None for value in db_params.values()):
        print("Error: Database environment variables not set.", file=sys.stderr)
        print("Please set DB_HOST, DB_PORT, DB_NAME, DB_USER, and DB_PASS.", file=sys.stderr)
        return False

    is_moderator = False
    conn = None
    try:
        conn = psycopg2.connect(**db_params)
        # Use a `with` statement for the cursor to ensure it's closed.
        with conn.cursor() as cur:
            # The query uses a placeholder (%s) for parameterization to prevent SQL injection.
            sql = "SELECT is_moderator FROM users WHERE username = %s"
            
            # Pass the parameter as a tuple to the execute method.
            cur.execute(sql, (username,))
            
            result = cur.fetchone()
            if result:
                is_moderator = result[0]

    except psycopg2.Error as e:
        # In a production environment, log this error to a secure logging system.
        print(f"Database query failed: {e}", file=sys.stderr)
        return False # Fail closed on any exception.
    finally:
        if conn:
            conn.close()
            
    return is_moderator

def main():
    """Main function to run test cases."""
    print("Running moderator check tests...")
    print("---------------------------------")
    print("This test assumes a PostgreSQL database is running and")
    print("the required environment variables and table are set up.")
    print("---------------------------------")

    # 5 Test cases
    test_users = [
        "alice",          # Expected: true (existing moderator)
        "bob",            # Expected: false (existing non-moderator)
        "eve",            # Expected: false (non-existent user)
        "' OR '1'='1",    # Expected: false (SQL injection attempt)
        ""                # Expected: false (invalid input)
    ]
    
    for user in test_users:
        user_display = user if user else "<empty>"
        result = is_user_moderator(user)
        print(f"Checking if user '{user_display}' is a moderator... {result}")

if __name__ == "__main__":
    main()