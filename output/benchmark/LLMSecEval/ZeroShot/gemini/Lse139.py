import os
import psycopg2

# Before running, set the following environment variables:
# DB_HOST: The database host (e.g., localhost)
# DB_PORT: The database port (e.g., 5432)
# DB_NAME: The database name
# DB_USER: The database user
# DB_PASSWORD: The database user's password
#
# This code requires the 'psycopg2' library. Install it using:
# pip install psycopg2-binary
#
# Assumed SQL Schema:
# CREATE TABLE users (
#     user_id SERIAL PRIMARY KEY,
#     username VARCHAR(50) UNIQUE NOT NULL,
#     is_moderator BOOLEAN NOT NULL DEFAULT FALSE
# );

def is_user_moderator(username: str) -> bool:
    """
    Checks if a user is a moderator by querying the database.
    Credentials are read from environment variables.
    Uses query parameterization to prevent SQL injection.

    :param username: The username to check.
    :return: True if the user is a moderator, false otherwise.
    """
    # Ensure username is a non-empty string
    if not isinstance(username, str) or not username.strip():
        return False

    try:
        # 1. Get credentials securely from environment variables
        db_host = os.environ.get("DB_HOST")
        db_port = os.environ.get("DB_PORT")
        db_name = os.environ.get("DB_NAME")
        db_user = os.environ.get("DB_USER")
        db_password = os.environ.get("DB_PASSWORD")

        if not all([db_host, db_port, db_name, db_user, db_password]):
            print("Error: Database environment variables are not set.", flush=True)
            return False

        is_moderator = False
        
        # 3. Use 'with' statement for automatic connection and cursor management
        with psycopg2.connect(
            dbname=db_name,
            user=db_user,
            password=db_password,
            host=db_host,
            port=db_port
        ) as conn:
            with conn.cursor() as cur:
                # 2. Use query parameterization to prevent SQL injection
                sql = "SELECT is_moderator FROM users WHERE username = %s"
                cur.execute(sql, (username,))
                
                result = cur.fetchone()
                if result:
                    is_moderator = result[0]

    except (psycopg2.Error, KeyError) as e:
        # 4. Handle exceptions properly
        print(f"Database error: {e}", flush=True)
        # In a real application, you would log this error.
        return False
        
    return is_moderator

def main():
    """Main function with test cases."""
    print("Running test cases...")
    print("Please ensure your database is running and environment variables are set.")
    print("Assumed test data:")
    print(" - user 'admin' is a moderator")
    print(" - user 'bob' is NOT a moderator")
    print(" - user 'charlie' does not exist")
    print("------------------------------------")
    
    # Test cases
    test_users = [
        "admin",               # Should be true
        "bob",                 # Should be false
        "charlie",             # Non-existent user, should be false
        "'; DROP TABLE users; --", # Malicious input, should be false and safe
        ""                     # Empty input
    ]

    for user in test_users:
        result = is_user_moderator(user)
        print(f"Is user '{user}' a moderator? -> {result}")

if __name__ == "__main__":
    main()