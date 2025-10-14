import urllib.request
import urllib.parse
import re
import os
import shutil
import tempfile
from pathlib import Path
import ssl
import certifi

# Regex to validate filename. Allows alphanumeric, underscore, dot, hyphen.
FILENAME_REGEX = re.compile(r"^[a-zA-Z0-9._-]+$")
DOWNLOAD_DIR = "downloads_python"

def is_valid_filename(filename: str) -> bool:
    """Validates a filename against a secure pattern."""
    return filename and FILENAME_REGEX.match(filename) is not None

def download_file(base_url: str, filename: str) -> Path | None:
    """
    Downloads a file from a base URL given a filename.
    
    Args:
        base_url: The base URL of the server.
        filename: The name of the file to download.
    
    Returns:
        A Path object to the downloaded file, or None on failure.
    """
    if not is_valid_filename(filename):
        print(f"Error: Invalid filename provided: {filename}")
        return None

    download_path = Path(DOWNLOAD_DIR)
    try:
        download_path.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        print(f"Error: Could not create download directory: {e}")
        return None

    destination_path = (download_path / filename).resolve()
    # Final check to ensure the path is within the intended directory
    if download_path.resolve() not in destination_path.parents:
        print("Error: Directory traversal attempt detected.")
        return None

    temp_file_handle, temp_file_path_str = -1, ""
    try:
        encoded_filename = urllib.parse.quote(filename)
        full_url = base_url + encoded_filename
        
        # Use certifi's CA bundle for robust SSL certificate validation
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        
        with urllib.request.urlopen(full_url, context=ssl_context, timeout=20) as response:
            if response.status != 200:
                print(f"Error: Failed to download file. Status code: {response.status}")
                return None
            
            # Create a temporary file securely
            temp_file_handle, temp_file_path_str = tempfile.mkstemp(suffix=".tmp", dir=download_path)
            temp_file_path = Path(temp_file_path_str)

            with os.fdopen(temp_file_handle, 'wb') as f_temp:
                shutil.copyfileobj(response, f_temp)
            
            # Atomically move the temporary file to the final destination
            shutil.move(temp_file_path, destination_path)
            print(f"Successfully downloaded: {filename} to {destination_path}")
            return destination_path

    except urllib.error.URLError as e:
        print(f"Error during download: {e.reason}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        # Clean up temporary file if it still exists
        if temp_file_path_str and os.path.exists(temp_file_path_str):
            os.remove(temp_file_path_str)

    return None

def main():
    """Main function with test cases."""
    base_url = "https://raw.githubusercontent.com/git/git/master/"

    print("--- Test Case 1: Valid File ---")
    download_file(base_url, "README.md")

    print("\n--- Test Case 2: Non-existent File ---")
    download_file(base_url, "NON_EXISTENT_FILE.txt")

    print("\n--- Test Case 3: Path Traversal Attempt ---")
    download_file(base_url, "../../etc/passwd")
    
    print("\n--- Test Case 4: Invalid Characters ---")
    download_file(base_url, "file?name=value")

    print("\n--- Test Case 5: Empty Filename ---")
    download_file(base_url, "")

if __name__ == "__main__":
    main()