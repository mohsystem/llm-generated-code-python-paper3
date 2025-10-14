
import psycopg2
from psycopg2 import Error

def create_postgres_connection(host, port, database, username, password):
    connection = None
    try:
        connection = psycopg2.connect(
            host=host,
            port=port,
            database=database,
            user=username,
            password=password
        )
        print("Connection established successfully!")
    except Error as e:
        print(f"Error connecting to database: {e}")
    return connection

if __name__ == "__main__":
    # Test case 1: Standard connection
    conn1 = create_postgres_connection("localhost", 5432, "testdb", "postgres", "password")
    if conn1:
        conn1.close()

    # Test case 2: Custom port
    conn2 = create_postgres_connection("localhost", 5433, "mydb", "admin", "admin123")
    if conn2:
        conn2.close()

    # Test case 3: Remote host
    conn3 = create_postgres_connection("192.168.1.100", 5432, "production", "dbuser", "securepass")
    if conn3:
        conn3.close()

    # Test case 4: Different database
    conn4 = create_postgres_connection("localhost", 5432, "analytics", "analyst", "analyze123")
    if conn4:
        conn4.close()

    # Test case 5: Development environment
    conn5 = create_postgres_connection("dev.example.com", 5432, "devdb", "developer", "dev@2024")
    if conn5:
        conn5.close()
