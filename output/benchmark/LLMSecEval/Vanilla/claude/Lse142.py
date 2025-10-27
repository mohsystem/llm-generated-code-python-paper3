
import sqlite3
import os

def unsubscribe(email):
    db_path = "emaildb.db"
    conn = None
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if email exists
        cursor.execute("SELECT email FROM subscribers WHERE email = ?", (email,))
        result = cursor.fetchone()
        
        if result:
            # Email exists, remove it
            cursor.execute("DELETE FROM subscribers WHERE email = ?", (email,))
            conn.commit()
            
            if cursor.rowcount > 0:
                return f"Successfully unsubscribed: {email}"
            else:
                return "Error occurred while unsubscribing"
        else:
            return f"Email not found in database: {email}"
    
    except sqlite3.Error as e:
        return f"Database error: {str(e)}"
    
    finally:
        if conn:
            conn.close()

def main():
    # Test cases
    print("Test Case 1:")
    print(unsubscribe("user1@example.com"))
    
    print("\\nTest Case 2:")
    print(unsubscribe("user2@example.com"))
    
    print("\\nTest Case 3:")
    print(unsubscribe("notindb@example.com"))
    
    print("\\nTest Case 4:")
    print(unsubscribe("user3@example.com"))
    
    print("\\nTest Case 5:")
    print(unsubscribe("invalid@test.com"))

if __name__ == "__main__":
    main()
