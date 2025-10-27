import os
import psycopg2

# To run this code, you need:
# 1. A PostgreSQL database.
# 2. A 'users' table in the database with schema:
#    CREATE TABLE users (
#        id SERIAL PRIMARY KEY,
#        username VARCHAR(50) UNIQUE NOT NULL,
#        is_moderator BOOLEAN NOT NULL DEFAULT FALSE
#    );
# 3. The psycopg2 library installed.
#    pip install psycopg2-binary
# 4. The following environment variables set:
#    DB_HOST=your_database_host
#    DB_PORT=your_database_port (e.g., 5432)
#    DB_NAME=your_database_name
#    DB_USER=your_username
#    DB_PASSWORD=your_password

def is_user_moderator(username: str) -> bool:
    """
    Connects to the database and checks if a given user is a moderator.
    """
    is_moderator = False
    conn = None
    try:
        # Get credentials from environment variables
        conn = psycopg2.connect(
            host=os.getenv("DB_HOST"),
            port=os.getenv("DB_PORT"),
            dbname=os.getenv("DB_NAME"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD")
        )
        
        # Use a 'with' statement for the cursor to ensure it's closed
        with conn.cursor() as cur:
            sql = "SELECT is_moderator FROM users WHERE username = %s"
            cur.execute(sql, (username,))
            
            result = cur.fetchone()
            if result:
                is_moderator = result[0]

    except (Exception, psycopg2.DatabaseError) as error:
        print(f"Error: {error}")
    finally:
        if conn is not None:
            conn.close()
            
    return is_moderator

def main():
    """Main function to run test cases."""
    # --- Test Cases ---
    # Note: These tests require a database connection and pre-populated data.
    # For example, insert a user 'admin' who is a moderator and 'guest' who is not.
    # INSERT INTO users (username, is_moderator) VALUES ('admin', TRUE);
    # INSERT INTO users (username, is_moderator) VALUES ('guest', FALSE);
    # INSERT INTO users (username, is_moderator) VALUES ('moderator1', TRUE);

    print("Checking 5 test cases. This requires a live database connection and pre-configured environment variables.")
    
    # Test Case 1: A user who is a moderator
    user1 = "admin"
    print(f"Is '{user1}' a moderator? {is_user_moderator(user1)}")

    # Test Case 2: A user who is not a moderator
    user2 = "guest"
    print(f"Is '{user2}' a moderator? {is_user_moderator(user2)}")
    
    # Test Case 3: Another user who is a moderator
    user3 = "moderator1"
    print(f"Is '{user3}' a moderator? {is_user_moderator(user3)}")

    # Test Case 4: A user who does not exist in the database
    user4 = "nonexistent_user"
    print(f"Is '{user4}' a moderator? {is_user_moderator(user4)}")

    # Test Case 5: A user with a potentially malicious name (handled by parameterization)
    user5 = "'; DROP TABLE users; --"
    print(f"Is '{user5}' a moderator? {is_user_moderator(user5)}")

if __name__ == "__main__":
    main()