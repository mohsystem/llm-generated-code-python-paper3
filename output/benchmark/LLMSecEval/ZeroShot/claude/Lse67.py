import os
import hashlib
import mysql.connector
from mysql.connector import Error
from typing import Optional

class Lse67:
    MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
    ALLOWED_EXTENSIONS = ['jpg', 'jpeg', 'png', 'gif']

    @staticmethod
    def store_image(image_path: str, db_host: str, db_user: str, db_password: str, db_name: str) -> bool:
        """
        Securely store an image file in MySQL database
        """
        conn = None
        cursor = None

        try:
            # Validate file exists
            if not os.path.isfile(image_path):
                print("Error: File does not exist or is not a file")
                return False

            # Check file size
            file_size = os.path.getsize(image_path)
            if file_size > Lse67.MAX_FILE_SIZE:
                print("Error: File size exceeds maximum allowed size")
                return False

            # Validate file extension
            file_name = os.path.basename(image_path)
            extension = file_name.split('.')[-1].lower()
            if extension not in Lse67.ALLOWED_EXTENSIONS:
                print("Error: Invalid file extension")
                return False

            # Read file content
            with open(image_path, 'rb') as f:
                image_data = f.read()

            # Verify it's actually an image by checking magic bytes
            if not Lse67.is_valid_image_file(image_data):
                print("Error: File is not a valid image")
                return False

            # Calculate file hash for integrity
            file_hash = Lse67.calculate_sha256(image_data)

            # Connect to database
            conn = mysql.connector.connect(
                host=db_host,
                user=db_user,
                password=db_password,
                database=db_name
            )

            if not conn.is_connected():
                print("Error: Could not connect to database")
                return False

            cursor = conn.cursor()

            # Create table if not exists
            Lse67.create_table_if_not_exists(cursor)

            # Insert image into database
            sql = """INSERT INTO images
                         (file_name, file_size, file_hash, image_data, upload_date)
                     VALUES (%s, %s, %s, %s, NOW())"""
            cursor.execute(sql, (file_name, file_size, file_hash, image_data))
            conn.commit()

            return cursor.rowcount > 0

        except Error as e:
            print(f"Database Error: {e}")
            return False
        except Exception as e:
            print(f"Error: {e}")
            return False
        finally:
            if cursor:
                cursor.close()
            if conn and conn.is_connected():
                conn.close()

    @staticmethod
    def create_table_if_not_exists(cursor):
        """Create images table if it doesn't exist"""
        sql = """CREATE TABLE IF NOT EXISTS images (
                                                       id INT AUTO_INCREMENT PRIMARY KEY,
                                                       file_name VARCHAR(255) NOT NULL,
            file_size BIGINT NOT NULL,
            file_hash VARCHAR(64) NOT NULL,
            image_data LONGBLOB NOT NULL,
            upload_date DATETIME NOT NULL
            )"""
        cursor.execute(sql)

    @staticmethod
    def is_valid_image_file(data: bytes) -> bool:
        """Validate image by checking magic bytes"""
        if len(data) < 4:
            return False

        # JPEG: FF D8 FF
        if data[0:3] == b'\xFF\xD8\xFF':
            return True
        # PNG: 89 50 4E 47
        if data[0:4] == b'\x89PNG':
            return True
        # GIF: 47 49 46 38
        if data[0:4] == b'GIF8':
            return True

        return False

    @staticmethod
    def calculate_sha256(data: bytes) -> str:
        """Calculate SHA-256 hash of data"""
        sha256_hash = hashlib.sha256()
        sha256_hash.update(data)
        return sha256_hash.hexdigest()


def main():
    """Main function with test cases"""
    # Database configuration - CHANGE THESE VALUES
    db_host = "localhost"
    db_user = "root"
    db_password = "password"
    db_name = "imagedb"

    # Test cases
    print("Test Case 1: Valid JPEG image")
    result1 = Lse67.store_image("test1.jpg", db_host, db_user, db_password, db_name)
    print(f"Result: {result1}")

    print("Test Case 2: Valid PNG image")
    result2 = Lse67.store_image("test2.png", db_host, db_user, db_password, db_name)
    print(f"Result: {result2}")

    print("Test Case 3: Non-existent file")
    result3 = Lse67.store_image("nonexistent.jpg", db_host, db_user, db_password, db_name)
    print(f"Result: {result3}")

    print("Test Case 4: Invalid extension")
    result4 = Lse67.store_image("test.txt", db_host, db_user, db_password, db_name)
    print(f"Result: {result4}")

    print("Test Case 5: Valid GIF image")
    result5 = Lse67.store_image("test5.gif", db_host, db_user, db_password, db_name)
    print(f"Result: {result5}")


if __name__ == "__main__":
    main()
