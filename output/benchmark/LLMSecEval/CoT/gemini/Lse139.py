import os
import psycopg2

def is_user_moderator(user_id: int) -> bool:
    """
    Connects to a PostgreSQL database using credentials from environment variables
    and checks if a user is a moderator.

    Required Environment Variables:
    DB_HOST: The database host (e.g., "localhost")
    DB_PORT: The database port (e.g., "5432")
    DB_NAME: The name of the database (e.g., "appdb")
    DB_USER: The database username
    DB_PASS: The database user's password

    Assumed table schema:
    CREATE TABLE users (
        user_id SERIAL PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        is_moderator BOOLEAN NOT NULL DEFAULT FALSE
    );

    :param user_id: The ID of the user to check.
    :return: True if the user is a moderator, False otherwise or if an error occurs.
    """
    try:
        host = os.environ.get("DB_HOST")
        port = os.environ.get("DB_PORT")
        dbname = os.environ.get("DB_NAME")
        user = os.environ.get("DB_USER")
        password = os.environ.get("DB_PASS")

        if not all([host, port, dbname, user, password]):
            print("Error: Database environment variables are not fully set.")
            return False

        # Use 'with' statements to ensure the connection and cursor are closed
        with psycopg2.connect(
            host=host,
            port=port,
            dbname=dbname,
            user=user,
            password=password
        ) as conn:
            with conn.cursor() as cur:
                sql = "SELECT is_moderator FROM users WHERE user_id = %s;"
                # Pass parameters separately to prevent SQL injection
                cur.execute(sql, (user_id,))
                
                result = cur.fetchone()
                
                if result:
                    return result[0]  # result is a tuple, e.g., (True,)
                
                return False # User not found
    except (Exception, psycopg2.Error) as error:
        print(f"Error while connecting to PostgreSQL: {error}")
        return False

# Main block for testing
if __name__ == "__main__":
    print("--- Python Test Cases ---")
    print("Note: This requires a running PostgreSQL database, 'psycopg2' library, and correctly set environment variables.")
    print("Install library with: pip install psycopg2-binary")
    print("See comments in the is_user_moderator function for setup details.")

    # Test cases (these will only work if you have a corresponding database setup)
    # Assume user 1 is a moderator, user 2 is not, and user 99 does not exist.
    moderator_user_id = 1
    regular_user_id = 2
    non_existent_user_id = 99
    another_moderator_id = 3
    another_regular_id = 4
    
    print(f"Is user {moderator_user_id} a moderator? {is_user_moderator(moderator_user_id)}")
    print(f"Is user {regular_user_id} a moderator? {is_user_moderator(regular_user_id)}")
    print(f"Is user {non_existent_user_id} a moderator? {is_user_moderator(non_existent_user_id)}")
    print(f"Is user {another_moderator_id} a moderator? {is_user_moderator(another_moderator_id)}")
    print(f"Is user {another_regular_id} a moderator? {is_user_moderator(another_regular_id)}")