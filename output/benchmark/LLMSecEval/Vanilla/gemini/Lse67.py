# Prerequisites for Python:
# 1. MySQL Server running.
# 2. A database created. For example: `CREATE DATABASE testdb;`
# 3. A table for storing images. For example:
#    CREATE TABLE images (
#        id INT AUTO_INCREMENT PRIMARY KEY,
#        name VARCHAR(255) NOT NULL,
#        data LONGBLOB NOT NULL
#    );
# 4. MySQL Connector for Python. Install it using pip:
#    pip install mysql-connector-python

import mysql.connector
import os

# --- IMPORTANT: UPDATE DATABASE CONNECTION DETAILS ---
DB_CONFIG = {
    'host': 'localhost',
    'user': 'your_username',
    'password': 'your_password',
    'database': 'testdb'
}

def store_image_in_db(file_path):
    """
    Stores an image file in the MySQL database.

    :param file_path: The path to the image file.
    :return: True if the image was stored successfully, False otherwise.
    """
    try:
        # Read the binary data from the file
        with open(file_path, 'rb') as f:
            binary_data = f.read()

        # Connect to the database
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()

        # Prepare the SQL query
        sql = "INSERT INTO images (name, data) VALUES (%s, %s)"
        file_name = os.path.basename(file_path)
        
        # Execute the query
        cursor.execute(sql, (file_name, binary_data))
        conn.commit()
        
        return True

    except mysql.connector.Error as e:
        print(f"Error connecting to MySQL or executing query: {e}")
        return False
    except IOError as e:
        print(f"Error reading file {file_path}: {e}")
        return False
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

def create_dummy_file(file_name):
    """Helper function to create a dummy file for testing."""
    try:
        with open(file_name, 'w') as f:
            f.write(f"This is dummy content for {file_name}")
    except IOError as e:
        print(f"Could not create dummy file: {e}")

def main():
    """Main function with test cases."""
    test_files = [
        "test_image_1.jpg",
        "test_image_2.png",
        "document.pdf",
        "archive.zip",
        "data.bin"
    ]

    for i, file_name in enumerate(test_files):
        # Create a dummy file for the test
        create_dummy_file(file_name)
        
        print(f"--- Test Case {i + 1} ---")
        print(f"Attempting to store: {file_name}")
        
        success = store_image_in_db(file_name)
        if success:
            print(f"Successfully stored '{file_name}' in the database.")
        else:
            print(f"Failed to store '{file_name}' in the database.")

        # Clean up the dummy file
        if os.path.exists(file_name):
            os.remove(file_name)
        print()

if __name__ == "__main__":
    main()