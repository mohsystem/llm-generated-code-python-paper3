import os
import re
from pathlib import Path

class Task129:
    BASE_DIRECTORY = "./secure_files/"
    ALLOWED_EXTENSIONS = {".txt", ".json", ".xml", ".csv", ".log"}
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
    SAFE_FILENAME_PATTERN = re.compile(r'^[a-zA-Z0-9_\\-\\.]+$')

    @staticmethod
    def retrieve_file(file_name):
        try:
            # Input validation
            if not file_name or not file_name.strip():
                return "Error: File name cannot be empty"

            file_name = file_name.strip()

            # Check for safe filename pattern
            if not Task129.SAFE_FILENAME_PATTERN.match(file_name):
                return "Error: Invalid file name format. Only alphanumeric, dash, underscore and dot allowed"

            # Check file extension
            extension = Path(file_name).suffix.lower()
            if extension not in Task129.ALLOWED_EXTENSIONS:
                return f"Error: File type not allowed. Allowed types: {Task129.ALLOWED_EXTENSIONS}"

            # Prevent path traversal attacks
            base_path = Path(Task129.BASE_DIRECTORY).resolve()
            file_path = (base_path / file_name).resolve()

            if not str(file_path).startswith(str(base_path)):
                return "Error: Path traversal detected. Access denied"

            # Check if file exists
            if not file_path.exists():
                return "Error: File not found"

            # Check if it's a file (not directory)
            if not file_path.is_file():
                return "Error: Invalid file type"

            # Check file size
            if file_path.stat().st_size > Task129.MAX_FILE_SIZE:
                return "Error: File size exceeds maximum allowed size"

            # Read file content
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            return f"Success: File retrieved\nContent:\n{content}"

        except IOError as e:
            return f"Error: Unable to read file - {str(e)}"
        except Exception as e:
            return f"Error: Unexpected error - {str(e)}"

    @staticmethod
    def setup_test_environment():
        try:
            os.makedirs(Task129.BASE_DIRECTORY, exist_ok=True)

            # Create test files
            test_files = {
                "test1.txt": "This is a test file 1",
                "test2.json": '{"name": "test", "value": 123}',
                "test3.csv": "id,name,age\n1,John,30\n2,Jane,25"
            }

            for filename, content in test_files.items():
                with open(os.path.join(Task129.BASE_DIRECTORY, filename), 'w') as f:
                    f.write(content)
        except Exception as e:
            print(f"Setup error: {str(e)}")

def main():
    Task129.setup_test_environment()

    print("=== Secure File Retrieval System ===\n")

    # Test case 1: Valid file retrieval
    print("Test 1: Valid file retrieval")
    print(Task129.retrieve_file("test1.txt"))
    print("---\n")

    # Test case 2: Another valid file
    print("Test 2: Valid JSON file")
    print(Task129.retrieve_file("test2.json"))
    print("---\n")

    # Test case 3: Path traversal attempt
    print("Test 3: Path traversal attempt")
    print(Task129.retrieve_file("../../../etc/passwd"))
    print("---\n")

    # Test case 4: Invalid file extension
    print("Test 4: Invalid file extension")
    print(Task129.retrieve_file("test.exe"))
    print("---\n")

    # Test case 5: Non-existent file
    print("Test 5: Non-existent file")
    print(Task129.retrieve_file("nonexistent.txt"))
    print("---\n")

if __name__ == "__main__":
    main()
