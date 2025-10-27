import os

def upload_file(filename, content):
    """
    Handles the upload of a file by saving it to the 'uploads' folder.
    The 'uploads' folder is created in the same directory as the source file.
    This function mimics the behavior of p.save(os.path.join('uploads', filename)).

    :param filename: The name of the file to save.
    :param content: The string content to write into the file.
    :return: Boolean indicating success or failure.
    """
    upload_folder = 'uploads'
    try:
        # Ensure the uploads directory exists
        os.makedirs(upload_folder, exist_ok=True)

        # Construct the full file path
        file_path = os.path.join(upload_folder, filename)

        # Save the file
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print(f"Python: Successfully saved file to {os.path.abspath(file_path)}")
        return True
    except IOError as e:
        print(f"Python Error: Failed to save file. {e}")
        return False

if __name__ == '__main__':
    print("--- Python Test Cases ---")
    upload_file("python_test1.txt", "This is a test from Python.")
    upload_file("requirements.txt", "os\nsys\nrequests")
    upload_file("README.md", "# Project Title")
    upload_file("data.log", "INFO: User logged in.")
    upload_file("script.py", "print('Hello, World!')")
    print("-----------------------\n")