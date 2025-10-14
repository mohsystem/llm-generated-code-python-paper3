
import sqlite3
import os

class Task37:
    DB_NAME = "users.db"
    
    @staticmethod
    def initialize_database():
        try:
            conn = sqlite3.connect(Task37.DB_NAME)
            cursor = conn.cursor()
            
            create_table_sql = """CREATE TABLE IF NOT EXISTS users (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                username TEXT NOT NULL UNIQUE,\n                email TEXT,\n                fullname TEXT)"""
            cursor.execute(create_table_sql)
            
            users_data = [
                ('john_doe', 'john@example.com', 'John Doe'),
                ('jane_smith', 'jane@example.com', 'Jane Smith'),
                ('bob_wilson', 'bob@example.com', 'Bob Wilson'),
                ('alice_brown', 'alice@example.com', 'Alice Brown'),
                ('charlie_davis', 'charlie@example.com', 'Charlie Davis')
            ]
            
            for user in users_data:
                try:
                    cursor.execute("INSERT INTO users (username, email, fullname) VALUES (?, ?, ?)", user)
                except sqlite3.IntegrityError:
                    pass
            
            conn.commit()
            conn.close()
            
        except sqlite3.Error as e:
            return f"Database initialization error: {e}"
    
    @staticmethod
    def get_user_info(username):
        query = "SELECT * FROM users WHERE username = ?"
        result = []
        
        try:
            conn = sqlite3.connect(Task37.DB_NAME)
            cursor = conn.cursor()
            
            cursor.execute(query, (username,))
            row = cursor.fetchone()
            
            if row:
                result.append("User found:")
                result.append(f"ID: {row[0]}")
                result.append(f"Username: {row[1]}")
                result.append(f"Email: {row[2]}")
                result.append(f"Full Name: {row[3]}")
            else:
                result.append(f"User not found: {username}")
            
            conn.close()
            
        except sqlite3.Error as e:
            result.append(f"Database error: {e}")
        
        return "\\n".join(result)


if __name__ == "__main__":
    Task37.initialize_database()
    
    print("Test Case 1:")
    print(Task37.get_user_info("john_doe"))
    print("\\n" + "=" * 50 + "\\n")
    
    print("Test Case 2:")
    print(Task37.get_user_info("jane_smith"))
    print("\\n" + "=" * 50 + "\\n")
    
    print("Test Case 3:")
    print(Task37.get_user_info("alice_brown"))
    print("\\n" + "=" * 50 + "\\n")
    
    print("Test Case 4:")
    print(Task37.get_user_info("nonexistent_user"))
    print("\\n" + "=" * 50 + "\\n")
    
    print("Test Case 5:")
    print(Task37.get_user_info("charlie_davis"))
