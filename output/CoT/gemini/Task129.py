import os
import requests

def retrieve_file(base_url, file_name, save_dir):
    """
    Retrieves a file from a server and saves it locally.

    :param base_url: The base URL of the server directory (e.g., "https://example.com/files/").
    :param file_name: The name of the file to retrieve. Must be a simple filename.
    :param save_dir: The local directory where the file will be saved.
    :return: True if successful, False otherwise.
    """
    # 1. Security: Input validation to prevent Path Traversal
    if not file_name or os.path.basename(file_name) != file_name:
        print(f"Error: Invalid file name '{file_name}'. Must be a simple name without path separators.")
        return False

    try:
        # 2. Security: Construct URL from a fixed base to prevent SSRF
        if not base_url.endswith('/'):
            base_url += '/'
        url = base_url + file_name

        # 3. Security: Set a timeout to prevent DoS from slow servers
        with requests.get(url, stream=True, timeout=10) as r:
            # Check for HTTP errors (e.g., 404 Not Found)
            r.raise_for_status()

            # Securely construct the save path
            save_path = os.path.join(save_dir, file_name)

            # Ensure the save directory exists
            os.makedirs(save_dir, exist_ok=True)

            # Write the file in chunks for memory efficiency
            with open(save_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            print(f"File downloaded successfully to: {save_path}")
            return True

    except requests.exceptions.RequestException as e:
        print(f"An error occurred during download: {e}")
        return False
    except IOError as e:
        print(f"An error occurred writing to file: {e}")
        return False

def main():
    # Base URL of a public repository for testing purposes
    base_url = "https://raw.githubusercontent.com/gittar-und-fuchtel/md5-python-java-c/master/"
    # Local directory to save downloaded files
    save_dir = "downloads_python"

    print("--- Running Python Test Cases ---")
    
    # Test Case 1: Valid file
    print("\n[Test 1: Valid File]")
    retrieve_file(base_url, "README.md", save_dir)

    # Test Case 2: File not found
    print("\n[Test 2: Non-existent File]")
    retrieve_file(base_url, "non_existent_file.txt", save_dir)

    # Test Case 3: Path Traversal attempt (should be blocked)
    print("\n[Test 3: Path Traversal Attempt]")
    retrieve_file(base_url, "../some_other_file.txt", save_dir)
    
    # Test Case 4: Absolute path attempt (should be blocked)
    print("\n[Test 4: Absolute Path Attempt]")
    retrieve_file(base_url, "/etc/passwd", save_dir)

    # Test Case 5: Empty filename (should be blocked)
    print("\n[Test 5: Empty Filename]")
    retrieve_file(base_url, "", save_dir)

if __name__ == "__main__":
    main()