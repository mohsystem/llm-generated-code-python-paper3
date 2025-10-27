# Prerequisites for Python:
# 1. MySQL Server running.
# 2. A database named 'testdb'.
# 3. A table created with the following SQL command:
#    CREATE TABLE images (
#        id INT AUTO_INCREMENT PRIMARY KEY,
#        name VARCHAR(255) NOT NULL,
#        data LONGBLOB NOT NULL
#    );
# 4. MySQL Connector for Python library. Install it using pip:
#    pip install mysql-connector-python

import mysql.connector
import os

# --- Database Configuration ---
# WARNING: Storing credentials in code is insecure. Use environment variables
# or a secrets management system in a production environment.
DB_CONFIG = {
    'host': 'localhost',
    'user': 'user', # Replace with your DB username
    'password': 'password', # Replace with your DB password
    'database': 'testdb'
}

def store_image(db_config, file_path):
    """
    Stores an image file in the MySQL database.

    :param db_config: A dictionary with database connection details.
    :param file_path: The path to the image file.
    :return: True if the image was stored successfully, False otherwise.
    """
    if not os.path.exists(file_path):
        print(f"Error: File not found at {file_path}")
        return False
        
    try:
        # Read the image file in binary mode
        with open(file_path, 'rb') as f:
            binary_data = f.read()
            
        # Use a context manager for the connection to ensure it's closed
        with mysql.connector.connect(**db_config) as conn:
            with conn.cursor() as cursor:
                # Parameterized query prevents SQL injection
                sql = "INSERT INTO images (name, data) VALUES (%s, %s)"
                file_name = os.path.basename(file_path)
                
                # The connector handles the conversion of binary_data to a BLOB
                cursor.execute(sql, (file_name, binary_data))
                
                conn.commit()
                return cursor.lastrowid > 0

    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return False
    except IOError as err:
        print(f"File reading error: {err}")
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return False

def main():
    """Main function with 5 test cases"""
    # --- Test Setup ---
    # Create dummy files for testing
    dummy_image_path = "test_image.png"
    empty_image_path = "empty_image.png"
    try:
        # Create a small binary file to simulate an image
        with open(dummy_image_path, 'wb') as f:
            f.write(b'\x89PNG\x01\x02\x03\x04')
        # Create an empty file
        with open(empty_image_path, 'wb') as f:
            pass
    except IOError as e:
        print(f"Failed to create test files: {e}")
        return
        
    print("Running Python Image Storage Tests...")

    # Test Case 1: Store a valid image file.
    print("\n--- Test Case 1: Store a valid image ---")
    success1 = store_image(DB_CONFIG, dummy_image_path)
    print(f"Result: {'SUCCESS' if success1 else 'FAILURE'}")

    # Test Case 2: Store the same image with a different name.
    print("\n--- Test Case 2: Store another valid image ---")
    another_image_path = "another_image.jpg"
    with open(another_image_path, 'wb') as f:
        f.write(b'\x89JPG\x01\x02\x03\x04')
    success2 = store_image(DB_CONFIG, another_image_path)
    print(f"Result: {'SUCCESS' if success2 else 'FAILURE'}")

    # Test Case 3: Try to store a non-existent file.
    print("\n--- Test Case 3: Store a non-existent file ---")
    success3 = store_image(DB_CONFIG, "non_existent_file.jpg")
    print(f"Result: {'SUCCESS' if success3 else 'FAILURE'}")

    # Test Case 4: Store a file with a long name.
    print("\n--- Test Case 4: Store a file with a long name ---")
    long_name_path = "a_very_long_file_name_to_test_database_field_limits_and_handling_of_such_cases_0123456789.bin"
    with open(long_name_path, 'wb') as f:
        f.write(b'long name test')
    success4 = store_image(DB_CONFIG, long_name_path)
    print(f"Result: {'SUCCESS' if success4 else 'FAILURE'}")
    
    # Test Case 5: Store an empty file.
    print("\n--- Test Case 5: Store an empty file ---")
    success5 = store_image(DB_CONFIG, empty_image_path)
    print(f"Result: {'SUCCESS' if success5 else 'FAILURE'}")
    
    # --- Cleanup ---
    print("\nCleaning up test files...")
    for f in [dummy_image_path, another_image_path, long_name_path, empty_image_path]:
        if os.path.exists(f):
            os.remove(f)
    print("Done.")

if __name__ == "__main__":
    main()