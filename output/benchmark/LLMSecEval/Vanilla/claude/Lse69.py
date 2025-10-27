
import base64

def upload_image(input_image_path, output_file_path):
    try:
        # Read the image file in binary mode
        with open(input_image_path, 'rb') as image_file:
            image_data = image_file.read()
        
        # Encode the image using base64
        encoded_image = base64.b64encode(image_data).decode('utf-8')
        
        # Write the encoded image to a file
        with open(output_file_path, 'w') as output_file:
            output_file.write(encoded_image)
        
        print("Image uploaded and encoded successfully!")
        return True
    except Exception as e:
        print(f"Error uploading image: {str(e)}")
        return False

if __name__ == "__main__":
    # Test cases
    print("Test Case 1:")
    upload_image("test_image1.jpg", "encoded_image1.txt")
    
    print("\\nTest Case 2:")
    upload_image("test_image2.png", "encoded_image2.txt")
    
    print("\\nTest Case 3:")
    upload_image("test_image3.gif", "encoded_image3.txt")
    
    print("\\nTest Case 4:")
    upload_image("test_image4.bmp", "encoded_image4.txt")
    
    print("\\nTest Case 5:")
    upload_image("test_image5.jpeg", "encoded_image5.txt")
