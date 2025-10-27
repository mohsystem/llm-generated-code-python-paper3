import sqlite3
import base64
import os
import sys
import pathlib
import stat

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB

def upload_image(conn, file_path_str):
    """
    Reads an image, converts it to Base64, and inserts it into the database.
    This function uses a secure file opening pattern (open -> fstat -> read).

    :param conn: The database connection object.
    :param file_path_str: The path to the image file (must be a simple filename).
    :return: True if the upload was successful, False otherwise.
    """
    
    # Rule #1, #5: Input validation. Ensure it's a simple filename, no path components.
    if os.path.dirname(file_path_str) or not file_path_str:
        print(f"Error: Invalid file path '{file_path_str}'. Only simple filenames are allowed.", file=sys.stderr)
        return False

    fd = -1
    try:
        # Rule #6: Secure open-then-use pattern to prevent TOCTOU races.
        # O_NOFOLLOW prevents following symlinks.
        flags = os.O_RDONLY
        if hasattr(os, 'O_NOFOLLOW'):
            flags |= os.O_NOFOLLOW
        
        fd = os.open(file_path_str, flags)
        
        # Get file status from the file descriptor
        file_stat = os.fstat(fd)

        # Ensure it's a regular file
        if not stat.S_ISREG(file_stat.st_mode):
            print(f"Error: '{file_path_str}' is not a regular file.", file=sys.stderr)
            return False

        # Check file size
        file_size = file_stat.st_size
        if file_size == 0:
            print("Error: File is empty.", file=sys.stderr)
            return False
        if file_size > MAX_FILE_SIZE:
            print(f"Error: File size {file_size} bytes exceeds the limit of {MAX_FILE_SIZE} bytes.", file=sys.stderr)
            return False

        # Read content from the file descriptor
        file_content = os.read(fd, file_size)
        
        # Encode to Base64
        encoded_string = base64.b64encode(file_content).decode('ascii')

        # Rule #2: Use parameterized queries to prevent SQL injection.
        sql = "INSERT INTO images(name, data) VALUES(?, ?)"
        cursor = conn.cursor()
        cursor.execute(sql, (file_path_str, encoded_string))
        conn.commit()
        print(f"Successfully uploaded {file_path_str}")
        return True

    except FileNotFoundError:
        print(f"Error: File not found at '{file_path_str}'.", file=sys.stderr)
        return False
    except OSError as e:
        print(f"Error opening or reading file: {e}", file=sys.stderr)
        return False
    except sqlite3.Error as e:
        print(f"Database error: {e}", file=sys.stderr)
        conn.rollback()
        return False
    finally:
        if fd != -1:
            os.close(fd)


def main():
    """Main function to set up DB and run test cases."""
    conn = None
    try:
        conn = sqlite3.connect(":memory:")
        print("Connected to in-memory SQLite database.")
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE images (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                data TEXT NOT NULL
            );
        """)
        conn.commit()
        print("Table 'images' created.")

        run_test_cases(conn)

    except sqlite3.Error as e:
        print(f"An error occurred: {e}", file=sys.stderr)
    finally:
        if conn:
            conn.close()


def create_dummy_file(filename, size):
    try:
        with open(filename, "wb") as f:
            if size > 0:
                f.write(os.urandom(size))
        return filename
    except IOError as e:
        print(f"Failed to create dummy file '{filename}': {e}", file=sys.stderr)
        return None

def run_test_cases(conn):
    print("\n--- Running Test Cases ---")
    
    # Test Case 1: Valid small PNG file
    valid_file = create_dummy_file("test.png", 1024)
    print("\n[Test 1] Uploading a valid small image...")
    if valid_file:
        upload_image(conn, valid_file)

    # Test Case 2: Valid small JPG file
    valid_file2 = create_dummy_file("image.jpg", 2048)
    print("\n[Test 2] Uploading another valid small image...")
    if valid_file2:
        upload_image(conn, valid_file2)

    # Test Case 3: Zero-byte file
    zero_byte_file = create_dummy_file("empty.gif", 0)
    print("\n[Test 3] Uploading a zero-byte file (should fail)...")
    if zero_byte_file:
        upload_image(conn, zero_byte_file)

    # Test Case 4: File too large
    large_file = create_dummy_file("large_file.bmp", MAX_FILE_SIZE + 1)
    print("\n[Test 4] Uploading a file that is too large (should fail)...")
    if large_file:
        upload_image(conn, large_file)
    
    # Test Case 5: Non-existent file
    print("\n[Test 5] Uploading a non-existent file (should fail)...")
    upload_image(conn, "nonexistent.jpg")

    # Verify database content
    verify_db_content(conn, 2)

    # Cleanup
    for f in [valid_file, valid_file2, zero_byte_file, large_file]:
        if f and os.path.exists(f):
            os.remove(f)
    print("\n--- Test Cases Finished ---")

def verify_db_content(conn, expected_rows):
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM images")
        count = cursor.fetchone()[0]
        print(f"\nVerification: Found {count} rows in the database. Expected {expected_rows}.")
        if count == expected_rows:
            print("Verification successful.")
        else:
            print("Verification failed.")
    except sqlite3.Error as e:
        print(f"Failed to verify database content: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()