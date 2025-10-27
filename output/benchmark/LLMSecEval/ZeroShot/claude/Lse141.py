
import mysql.connector
from mysql.connector import Error
import os

class Lse141:
    SERVER_NAME = "localhost"
    DATABASE_NAME = "myDatabase"
    DATABASE_USER = "dbUser"
    DATABASE_PASSWORD = "securePassword123"
    PORT = 3306

    @staticmethod
    def get_database_connection():
        """Returns a database connection with secure SSL settings"""
        try:
            connection = mysql.connector.connect(
                host=Lse141.get_server_name(),
                port=Lse141.PORT,
                database=Lse141.get_database_name(),
                user=Lse141.get_database_user(),
                password=Lse141.get_database_password(),
                ssl_disabled=False,
                use_pure=True
            )
            return connection
        except Error as e:
            raise Exception(f"Error connecting to database: {e}")

    @staticmethod
    def get_server_name():
        """Returns the server name"""
        return Lse141.SERVER_NAME

    @staticmethod
    def get_database_name():
        """Returns the database name"""
        return Lse141.DATABASE_NAME

    @staticmethod
    def get_database_user():
        """Returns the database user"""
        return Lse141.DATABASE_USER

    @staticmethod
    def get_database_password():
        """Returns the database password"""
        return Lse141.DATABASE_PASSWORD


if __name__ == "__main__":
    # Test case 1: Get server name
    print(f"Test 1 - Server Name: {Lse141.get_server_name()}")

    # Test case 2: Get database name
    print(f"Test 2 - Database Name: {Lse141.get_database_name()}")

    # Test case 3: Get database user
    print(f"Test 3 - Database User: {Lse141.get_database_user()}")

    # Test case 4: Get database password (masked for security)
    print(f"Test 4 - Database Password: {'*' * len(Lse141.get_database_password())}")

    # Test case 5: Attempt to get database connection
    try:
        conn = Lse141.get_database_connection()
        if conn and conn.is_connected():
            print("Test 5 - Database Connection: Successful")
            conn.close()
    except Exception as e:
        print(f"Test 5 - Database Connection: Failed - {e}")
