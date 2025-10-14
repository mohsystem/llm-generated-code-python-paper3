import os
import hashlib
import time
import re

class Task50:
    UPLOAD_DIR = "uploads"
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'jpg', 'jpeg', 'png', 'doc', 'docx'}

    @staticmethod
    def upload_file(filename, file_content):
        try:
            # Validate filename
            if not Task50.is_valid_filename(filename):
                return "Error: Invalid filename"

            # Check file size
            if len(file_content) > Task50.MAX_FILE_SIZE:
                return "Error: File size exceeds maximum allowed size (10MB)"

            # Check file extension
            extension = Task50.get_file_extension(filename)
            if extension.lower() not in Task50.ALLOWED_EXTENSIONS:
                return "Error: File type not allowed"

            # Create upload directory if it doesn't exist
            if not os.path.exists(Task50.UPLOAD_DIR):
                os.makedirs(Task50.UPLOAD_DIR)

            # Sanitize filename and create unique name
            sanitized_name = Task50.sanitize_filename(filename)
            unique_filename = Task50.generate_unique_filename(sanitized_name)
            filepath = os.path.join(Task50.UPLOAD_DIR, unique_filename)

            # Write file
            with open(filepath, 'wb') as f:
                f.write(file_content)

            # Calculate checksum
            checksum = Task50.calculate_checksum(file_content)

            return f"Success: File uploaded successfully. Filename: {unique_filename}, Size: {len(file_content)} bytes, Checksum: {checksum}"

        except Exception as e:
            return f"Error: Failed to upload file - {str(e)}"

    @staticmethod
    def is_valid_filename(filename):
        if not filename or not filename.strip():
            return False
        # Check for path traversal attempts
        if '..' in filename or '/' in filename or '\\' in filename:
            return False
        # Check for valid characters
        valid_pattern = re.compile(r'^[a-zA-Z0-9._-]+$')
        return bool(valid_pattern.match(filename))

    @staticmethod
    def get_file_extension(filename):
        if '.' in filename:
            return filename.rsplit('.', 1)[1]
        return ""

    @staticmethod
    def sanitize_filename(filename):
        return re.sub(r'[^a-zA-Z0-9._-]', '_', filename)

    @staticmethod
    def generate_unique_filename(filename):
        timestamp = str(int(time.time() * 1000))
        name, extension = filename.rsplit('.', 1)
        return f"{name}_{timestamp}.{extension}"

    @staticmethod
    def calculate_checksum(data):
        hash_obj = hashlib.sha256(data)
        return hash_obj.hexdigest()[:16]


if __name__ == "__main__":
    print("File Upload Server - Test Cases\n")

    # Test Case 1: Valid text file
    result1 = Task50.upload_file("test1.txt", b"Hello World!")
    print(f"Test 1: {result1}\n")

    # Test Case 2: Valid PDF file (simulated)
    result2 = Task50.upload_file("document.pdf", b"PDF content simulation")
    print(f"Test 2: {result2}\n")

    # Test Case 3: Invalid filename with path traversal
    result3 = Task50.upload_file("../../../etc/passwd", b"malicious content")
    print(f"Test 3: {result3}\n")

    # Test Case 4: Disallowed file extension
    result4 = Task50.upload_file("script.exe", b"executable content")
    print(f"Test 4: {result4}\n")

    # Test Case 5: Valid image file
    result5 = Task50.upload_file("photo.jpg", b"JPEG image data")
    print(f"Test 5: {result5}\n")
