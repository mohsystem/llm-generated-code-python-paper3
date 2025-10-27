
import os
import mysql.connector
from mysql.connector import Error
from datetime import datetime

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
ALLOWED_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.bmp']

def store_image_in_database(image_path, db_host, db_user, db_password, db_name):
    """Store an image file in MySQL database securely"""
    
    # Validate input
    if not image_path or not isinstance(image_path, str):
        print("Invalid image path")
        return False
    
    # Validate file existence
    if not os.path.exists(image_path) or not os.path.isfile(image_path):
        print("File does not exist or is not a valid file")
        return False
    
    # Validate file size
    file_size = os.path.getsize(image_path)
    if file_size > MAX_FILE_SIZE:
        print("File size exceeds maximum allowed size")
        return False
    
    # Validate file extension
    file_name = os.path.basename(image_path)
    file_ext = os.path.splitext(file_name)[1].lower()
    if file_ext not in ALLOWED_EXTENSIONS:
        print("Invalid file extension")
        return False
    
    connection = None
    cursor = None
    
    try:
        # Read image file
        with open(image_path, 'rb') as file:
            image_data = file.read()
        
        # Connect to database
        connection = mysql.connector.connect(
            host=db_host,
            user=db_user,
            password=db_password,
            database=db_name
        )
        
        if connection.is_connected():
            cursor = connection.cursor()
            
            # Use parameterized query to prevent SQL injection
            insert_query = """INSERT INTO images (filename, image_data, upload_date) \n                            VALUES (%s, %s, %s)"""
            
            upload_date = datetime.now()
            cursor.execute(insert_query, (file_name, image_data, upload_date))
            connection.commit()
            
            return True
            
    except mysql.connector.Error as e:
        print(f"Database error: {e}")
        return False
    except IOError as e:
        print(f"File reading error: {e}")
        return False
    except Exception as e:
        print(f"Unexpected error: {e}")
        return False
    finally:
        # Properly close resources
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

def main():
    db_host = "localhost"
    db_user = "root"
    db_password = "password"
    db_name = "imagedb"
    
    # Test cases
    print("Test 1 (valid image):", 
          store_image_in_database("test1.jpg", db_host, db_user, db_password, db_name))
    
    print("Test 2 (valid image):", 
          store_image_in_database("test2.png", db_host, db_user, db_password, db_name))
    
    print("Test 3 (None path):", 
          store_image_in_database(None, db_host, db_user, db_password, db_name))
    
    print("Test 4 (non-existent file):", 
          store_image_in_database("nonexistent.jpg", db_host, db_user, db_password, db_name))
    
    print("Test 5 (invalid extension):", 
          store_image_in_database("test.txt", db_host, db_user, db_password, db_name))

if __name__ == "__main__":
    main()
