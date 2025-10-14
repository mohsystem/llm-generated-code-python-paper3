import os
import random
import string
import tempfile

class Task88:
    @staticmethod
    def generate_random_unicode_string(length):
        unicode_chars = (string.ascii_letters + 
                         string.digits + 
                         "àáâãäåæçèéêëìíîïðñòóôõöøùúûüýþÿ" +
                         "ΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩ" +
                         "αβγδεζηθικλμνξοπρστυφχψω" +
                         "€£¥©®™")
        return ''.join(random.choices(unicode_chars, k=length))

    @staticmethod
    def create_temp_file_with_random_unicode_string():
        """
        Creates a temporary file with a random Unicode string using UTF-8 encoding.
        Returns the path to the file.
        """
        try:
            # 1. Create a temporary file. mkstemp is used to avoid race conditions.
            fd, file_path = tempfile.mkstemp(prefix="temp_unicode_", suffix=".txt")

            # 2. Create a random string.
            random_string = Task88.generate_random_unicode_string(100)

            # 3. Python strings are sequences of Unicode code points.
            # 4. Write the string results to the file using UTF-8 encoding.
            with os.fdopen(fd, 'w', encoding='utf-8') as tmp_file:
                tmp_file.write(random_string)
            
            # 5. Return the path of the temporary file.
            return file_path
        except IOError as e:
            print(f"Error creating or writing to temp file: {e}")
            return None

def main():
    for i in range(1, 6):
        print(f"Test Case {i}:")
        file_path = Task88.create_temp_file_with_random_unicode_string()
        if file_path:
            print(f"  Temporary file created at: {file_path}")
            try:
                # Optional: Read back to verify content.
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                print(f"  File content length: {len(content)}")
                print(f"  File content starts with: {content[:20]}...")

                # Cleanup the temporary file.
                os.remove(file_path)
                print("  Temporary file deleted.")
            except Exception as e:
                print(f"  Error during file verification or cleanup: {e}")
        else:
            print("  Failed to create temporary file.")
        print()

if __name__ == "__main__":
    main()