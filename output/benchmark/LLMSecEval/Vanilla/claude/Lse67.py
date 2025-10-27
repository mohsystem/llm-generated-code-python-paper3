
import mysql.connector
import os

def store_image_in_database(image_path, db_config=None):
    if db_config is None:
        db_config = {
            'host': 'localhost',
            'user': 'root',
            'password': 'password',
            'database': 'imagedb'
        }
    
    try:
        # Establish connection
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        
        # Read image file
        with open(image_path, 'rb') as file:
            image_data = file.read()
        
        image_name = os.path.basename(image_path)
        
        # Prepare SQL statement
        sql = "INSERT INTO images (image_name, image_data) VALUES (%s, %s)"
        
        # Execute query
        cursor.execute(sql, (image_name, image_data))
        conn.commit()
        
        cursor.close()
        conn.close()
        
        return True
        
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    # Test cases - Note: These require actual image files and MySQL setup
    print("Test Case 1:", store_image_in_database("test1.jpg"))
    print("Test Case 2:", store_image_in_database("test2.png"))
    print("Test Case 3:", store_image_in_database("test3.gif"))
    print("Test Case 4:", store_image_in_database("test4.bmp"))
    print("Test Case 5:", store_image_in_database("test5.jpeg"))
