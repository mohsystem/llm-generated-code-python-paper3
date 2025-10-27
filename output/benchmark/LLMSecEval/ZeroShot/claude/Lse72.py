import os
import re
import time
from pathlib import Path

class Lse72:
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'jpg', 'jpeg', 'png', 'doc', 'docx'}
    UPLOAD_DIR = 'uploads'

    @staticmethod
    def upload_file(file_content, filename):
        try:
            # Validate file size
            if len(file_content) > Lse72.MAX_FILE_SIZE:
                return "Error: File size exceeds maximum allowed size"

            # Sanitize filename
            sanitized_filename = Lse72.sanitize_filename(filename)
            if sanitized_filename is None:
                return "Error: Invalid filename"

            # Validate file extension
            if not Lse72.is_allowed_extension(sanitized_filename):
                return "Error: File type not allowed"

            # Create uploads directory if it doesn't exist
            Path(Lse72.UPLOAD_DIR).mkdir(exist_ok=True)

            # Generate unique filename
            unique_filename = Lse72.generate_unique_filename(sanitized_filename)
            file_path = os.path.join(Lse72.UPLOAD_DIR, unique_filename)

            # Save file
            with open(file_path, 'wb') as f:
                if isinstance(file_content, str):
                    f.write(file_content.encode())
                else:
                    f.write(file_content)

            return f"File uploaded successfully: {unique_filename}"

        except Exception as e:
            return f"Error: {str(e)}"

    @staticmethod
    def sanitize_filename(filename):
        if not filename:
            return None

        # Remove path traversal attempts
        filename = filename.replace('..', '')
        filename = filename.replace('/', '').replace('\\', '')

        # Allow only alphanumeric, dots, dashes, and underscores
        if not re.match(r'^[a-zA-Z0-9._-]+$', filename):
            return None

        return filename

    @staticmethod
    def is_allowed_extension(filename):
        if '.' not in filename:
            return False
        extension = filename.rsplit('.', 1)[1].lower()
        return extension in Lse72.ALLOWED_EXTENSIONS

    @staticmethod
    def generate_unique_filename(filename):
        timestamp = str(int(time.time() * 1000))
        if '.' in filename:
            name, extension = filename.rsplit('.', 1)
            return f"{name}_{timestamp}.{extension}"
        return f"{filename}_{timestamp}"


if __name__ == "__main__":
    # Test Case 1: Valid text file
    print(Lse72.upload_file("This is a test file content", "test1.txt"))

    # Test Case 2: Valid PDF file
    print(Lse72.upload_file(b'\x00' * 1024, "document.pdf"))

    # Test Case 3: Invalid extension
    print(Lse72.upload_file("malicious content", "malicious.exe"))

    # Test Case 4: Path traversal attempt
    print(Lse72.upload_file("hacker content", "../../../etc/passwd"))

    # Test Case 5: Valid image file
    print(Lse72.upload_file(b'\x00' * 2048, "photo.jpg"))
