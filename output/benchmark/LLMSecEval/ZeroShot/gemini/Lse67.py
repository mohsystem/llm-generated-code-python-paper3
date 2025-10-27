import mysql.connector
import os

# Note: You need to install the mysql-connector-python library.
# pip install mysql-connector-python
#
# SQL to create the necessary table:
# CREATE DATABASE IF NOT EXISTS image_db;
# USE image_db;
# CREATE TABLE IF NOT EXISTS images (
#     id INT AUTO_INCREMENT PRIMARY KEY,
#     filename VARCHAR(255) NOT NULL,
#     image_data LONGBLOB NOT NULL,
#     upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
# );

class Lse67:
    @staticmethod
    def store_image_in_db(db_config, file_path):
        """
        Stores an image file in a MySQL database.

        :param db_config: A dictionary with database connection details
                          (host, user, password, database).
        :param file_path: The path to the image file.
        :return: True if successful, False otherwise.
        """
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            print(f"Error: File does not exist or is not a regular file: {file_path}")
            return False

        try:
            with open(file_path, 'rb') as f:
                binary_data = f.read()
        except IOError as e:
            print(f"Error reading file {file_path}: {e}")
            return False

        conn = None
        try:
            conn = mysql.connector.connect(**db_config)
            if conn.is_connected():
                cursor = conn.cursor()
                
                # Use a parameterized query to prevent SQL injection
                sql_insert_query = "INSERT INTO images (filename, image_data) VALUES (%s, %s)"
                file_name = os.path.basename(file_path)
                insert_tuple = (file_name, binary_data)

                cursor.execute(sql_insert_query, insert_tuple)
                conn.commit()
                return True

        except mysql.connector.Error as e:
            print(f"Database Error: {e}")
            return False
        finally:
            if conn and conn.is_connected():
                conn.close()
        return False

def create_dummy_file(file_name):
    """Helper function to create a dummy file for testing."""
    with open(file_name, 'w') as f:
        f.write("This is a dummy file.")

if __name__ == '__main__':
    # --- Database Configuration ---
    # IMPORTANT: In a real application, do not hardcode credentials.
    # Use environment variables, a configuration file, or a secrets management service.
    db_config = {
        'host': 'localhost',
        'user': 'user',      # Replace with your MySQL username
        'password': 'password',  # Replace with your MySQL password
        'database': 'image_db'
    }

    # --- Test Cases ---
    print("Running 5 test cases...")
    dummy_file_name = "test_image.png"
    create_dummy_file(dummy_file_name)
    
    # Test Case 1: Successful Insertion
    print("\n--- Test Case 1: Successful Insertion ---")
    success1 = Lse67.store_image_in_db(db_config, dummy_file_name)
    print(f"Result: {'SUCCESS' if success1 else 'FAILURE'}")

    # Test Case 2: File Not Found
    print("\n--- Test Case 2: File Not Found ---")
    success2 = Lse67.store_image_in_db(db_config, "non_existent_file.jpg")
    print(f"Result: {'SUCCESS' if success2 else 'FAILURE'}")

    # Test Case 3: Invalid Database Password
    print("\n--- Test Case 3: Invalid Database Password ---")
    bad_db_config = db_config.copy()
    bad_db_config['password'] = 'wrong_password'
    success3 = Lse67.store_image_in_db(bad_db_config, dummy_file_name)
    print(f"Result: {'SUCCESS' if success3 else 'FAILURE'}")

    # Test Case 4: Path is a Directory (should fail)
    print("\n--- Test Case 4: Path is a Directory ---")
    success4 = Lse67.store_image_in_db(db_config, ".")  # Current directory
    print(f"Result: {'SUCCESS' if success4 else 'FAILURE'}")

    # Test Case 5: Another successful insertion
    print("\n--- Test Case 5: Another Successful Insertion ---")
    another_dummy_file = "another_test.jpg"
    create_dummy_file(another_dummy_file)
    success5 = Lse67.store_image_in_db(db_config, another_dummy_file)
    print(f"Result: {'SUCCESS' if success5 else 'FAILURE'}")
    
    # Cleanup dummy files
    if os.path.exists(dummy_file_name):
        os.remove(dummy_file_name)
    if os.path.exists(another_dummy_file):
        os.remove(another_dummy_file)