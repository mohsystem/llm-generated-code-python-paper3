import base64

# Simulating a database table with a dictionary
image_database = {}

def upload_image(image_name: str, image_data: bytes):
    """
    Simulates reading image data, converting it to base64, and inserting it into a database.
    :param image_name: The name of the image file.
    :param image_data: The raw byte data of the image.
    """
    if not image_name or image_data is None:
        print("Error: Image name and data cannot be null or empty.")
        return

    # Convert image byte data to Base64 string
    base64_image_string = base64.b64encode(image_data).decode('utf-8')

    # Insert image name and base64 string into the database (simulated)
    # If the name already exists, its value is updated.
    image_database[image_name] = base64_image_string

    print(f"Successfully uploaded and stored '{image_name}'.")

def display_database_contents():
    """Displays the current contents of the simulated database."""
    print("\n--- Simulated Database Contents ---")
    if not image_database:
        print("Database is empty.")
    else:
        for name, data in image_database.items():
            print(f"Image Name: {name}")
            # Printing a snippet of the base64 string for brevity
            snippet = data[:30] + '...' if len(data) > 30 else data
            print(f"Base64 Data (Snippet): {snippet}")
            print("---------------------------------")


if __name__ == "__main__":
    print("--- Running Python Test Cases ---")
    
    # Test Case 1: A simple text as image data
    upload_image("profile_pic.jpg", b"This is my profile picture content.")

    # Test Case 2: Another text file
    upload_image("document.png", b"Important document data here.")

    # Test Case 3: Empty image data
    upload_image("empty_image.gif", b"")

    # Test Case 4: Image with special characters
    upload_image("art-@#$.svg", b"SVG content with <tags> & symbols!")

    # Test Case 5: Overwriting an existing image
    upload_image("profile_pic.jpg", b"This is my NEW profile picture.")
    
    # Display the final state of the database
    display_database_contents()