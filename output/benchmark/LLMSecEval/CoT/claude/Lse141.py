
import os
import sqlite3
from typing import Optional

class Lse141:
    """Secure database configuration class using environment variables"""
    
    @staticmethod
    def get_database_connection():
        """Returns a secure database connection"""
        db_name = Lse141.get_database_name()
        db_user = Lse141.get_database_user()
        db_password = Lse141._get_database_password()
        
        if not all([db_name, db_user, db_password]):
            raise ValueError("Database configuration not properly set in environment variables")
        
        # Using SQLite for demonstration; adapt for MySQL/PostgreSQL as needed
        # For production, use proper connection pooling and parameterized queries
        try:
            conn = sqlite3.connect(db_name, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            return conn
        except Exception as e:
            raise ConnectionError(f"Failed to connect to database: {str(e)}")
    
    @staticmethod
    def get_server_name() -> str:
        """Returns server name from environment variable"""
        return os.getenv('DB_SERVER', 'localhost')
    
    @staticmethod
    def get_database_name() -> str:
        """Returns database name from environment variable"""
        return os.getenv('DB_NAME', 'defaultdb.db')
    
    @staticmethod
    def get_database_user() -> str:
        """Returns database user from environment variable"""
        return os.getenv('DB_USER', 'root')
    
    @staticmethod
    def _get_database_password() -> str:
        """Private method - Returns database password from environment variable"""
        return os.getenv('DB_PASSWORD', '')


def main():
    """Main function with test cases"""
    print("Test Case 1: Get Server Name")
    print(f"Server: {Lse141.get_server_name()}")
    
    print("\\nTest Case 2: Get Database Name")
    print(f"Database: {Lse141.get_database_name()}")
    
    print("\\nTest Case 3: Get Database User")
    print(f"User: {Lse141.get_database_user()}")
    
    print("\\nTest Case 4: Configuration Check")
    config_set = all([
        os.getenv('DB_SERVER'),
        os.getenv('DB_NAME'),
        os.getenv('DB_USER'),
        os.getenv('DB_PASSWORD')
    ])
    print(f"All configuration set: {config_set}")
    
    print("\\nTest Case 5: Database Connection Test")
    try:
        conn = Lse141.get_database_connection()
        print("Connection successful!")
        conn.close()
    except Exception as e:
        print(f"Connection failed: {str(e)}")


if __name__ == "__main__":
    main()
