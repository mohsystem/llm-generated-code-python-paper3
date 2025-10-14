
import psycopg2
from psycopg2 import OperationalError

def create_postgres_connection(host, port, database, username, password):
    connection = None
    try:
        connection = psycopg2.connect(
            host=host,
            port=port,
            database=database,
            user=username,
            password=password,
            sslmode='require',
            connect_timeout=10
        )
        print("Connected to PostgreSQL database successfully!")
    except OperationalError as e:
        print(f"Connection failed: {e}")
    return connection

def main():
    # Test case 1: Local connection
    conn1 = create_postgres_connection("localhost", 5432, "testdb", "user1", "pass1")
    if conn1:
        conn1.close()
    
    # Test case 2: Custom port
    conn2 = create_postgres_connection("localhost", 5433, "mydb", "admin", "admin123")
    if conn2:
        conn2.close()
    
    # Test case 3: Remote connection
    conn3 = create_postgres_connection("192.168.1.100", 5432, "proddb", "dbuser", "securepass")
    if conn3:
        conn3.close()
    
    # Test case 4: Different database
    conn4 = create_postgres_connection("localhost", 5432, "analytics", "analyst", "analyze123")
    if conn4:
        conn4.close()
    
    # Test case 5: Another local instance
    conn5 = create_postgres_connection("127.0.0.1", 5432, "devdb", "developer", "dev@2024")
    if conn5:
        conn5.close()

if __name__ == "__main__":
    main()
