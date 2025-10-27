
import sqlite3
import base64
import os

def init_database():
    conn = sqlite3.connect('images.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS images\n                     (id INTEGER PRIMARY KEY AUTOINCREMENT,\n                      name TEXT NOT NULL,\n                      image_data TEXT NOT NULL)''')
    conn.commit()
    conn.close()

def upload_image(image_path):
    try:
        if not os.path.exists(image_path):
            return False
        
        with open(image_path, 'rb') as image_file:
            image_bytes = image_file.read()
        
        base64_image = base64.b64encode(image_bytes).decode('utf-8')
        image_name = os.path.basename(image_path)
        
        conn = sqlite3.connect('images.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO images (name, image_data) VALUES (?, ?)",
                      (image_name, base64_image))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    init_database()
    
    # Test case 1: Upload a valid image
    print("Test 1:", upload_image("test_image1.jpg"))
    
    # Test case 2: Upload another valid image
    print("Test 2:", upload_image("test_image2.png"))
    
    # Test case 3: Upload non-existent image
    print("Test 3:", upload_image("non_existent.jpg"))
    
    # Test case 4: Upload with different path
    print("Test 4:", upload_image("images/photo.jpg"))
    
    # Test case 5: Upload another image
    print("Test 5:", upload_image("sample.bmp"))
