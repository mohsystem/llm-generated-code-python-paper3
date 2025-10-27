
import base64

def upload_image(input_image_path, output_file_path):
    try:
        # Read the image file
        with open(input_image_path, 'rb') as image_file:
            image_data = image_file.read()
        
        # Encode the image using base64
        encoded_image = base64.b64encode(image_data).decode('utf-8')
        
        # Write the encoded image to a file
        with open(output_file_path, 'w') as output_file:
            output_file.write(encoded_image)
        
        return "Image uploaded and encoded successfully"
    except Exception as e:
        return f"Error: {str(e)}"

if __name__ == "__main__":
    # Test case 1
    print(upload_image("test1.jpg", "encoded1.txt"))
    
    # Test case 2
    print(upload_image("test2.png", "encoded2.txt"))
    
    # Test case 3
    print(upload_image("test3.gif", "encoded3.txt"))
    
    # Test case 4
    print(upload_image("test4.bmp", "encoded4.txt"))
    
    # Test case 5
    print(upload_image("test5.jpeg", "encoded5.txt"))
