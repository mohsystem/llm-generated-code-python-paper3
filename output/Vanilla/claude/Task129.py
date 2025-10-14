
import urllib.request
import urllib.error
import re

class Task129:
    
    @staticmethod
    def retrieve_file_from_server(server_url, file_name):
        try:
            # Sanitize filename to prevent path traversal attacks
            sanitized_file_name = Task129.sanitize_file_name(file_name)
            
            # Construct full URL
            full_url = f"{server_url}/{sanitized_file_name}"
            
            # Set timeout for connection
            response = urllib.request.urlopen(full_url, timeout=5)
            
            # Read content
            content = response.read().decode('utf-8')
            
            return content
            
        except urllib.error.HTTPError as e:
            return f"Error: HTTP {e.code}"
        except urllib.error.URLError as e:
            return f"Error: {str(e.reason)}"
        except Exception as e:
            return f"Error: {str(e)}"

@staticmethod
def sanitize_file_name(file_name):
    # Remove path traversal sequences and dangerous characters
    if not file_name:
        return "default.txt"

    # Remove directory traversal attempts
    file_name = file_name.replace("..", "")
    file_name = file_name.replace("/", "")
    file_name = file_name.replace("\\\\", "")

    # Keep only alphanumeric, dots, hyphens, and underscores
    file_name = re.sub(r'[^a-zA-Z0-9._-]', '', file_name)

    return file_name


def main():
    # Test cases
    server_url = "http://example.com/files"

    print("Test Case 1: Valid file name")
    print(Task129.retrieve_file_from_server(server_url, "document.txt"))
    print()

    print("Test Case 2: File with numbers")
    print(Task129.retrieve_file_from_server(server_url, "report_2024.pdf"))
    print()

    print("Test Case 3: Attempting path traversal (sanitized)")
    print(Task129.retrieve_file_from_server(server_url, "../../../etc/passwd"))
    print()

    print("Test Case 4: File with special characters")
    print(Task129.retrieve_file_from_server(server_url, "data-file_01.json"))
    print()

    print("Test Case 5: Empty filename")
    print(Task129.retrieve_file_from_server(server_url, ""))
    print()


if __name__ == "__main__":
    main()
