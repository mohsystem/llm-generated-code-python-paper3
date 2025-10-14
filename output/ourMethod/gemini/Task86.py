# This script requires the 'requests' library.
# You can install it with: pip install requests

import requests
import subprocess
import os
import tempfile
import sys
from typing import Optional

def download_and_execute(url: Optional[str]) -> int:
    """
    Downloads an executable file from a given URL and executes it.
    WARNING: This function is inherently dangerous as it downloads and executes
    code from the internet. Only use with URLs from trusted sources.

    :param url: The URL of the .exe file to download.
    :return: 0 on success, non-zero on failure.
    """
    # Rule #3: Ensure all input is validated
    if not url:
        print("Error: URL is null or empty.", file=sys.stderr)
        return 1
    if not url.lower().startswith("https://"):
        print("Error: URL must use HTTPS.", file=sys.stderr)
        return 2
    if not url.lower().endswith(".exe"):
        print("Error: URL must point to an .exe file.", file=sys.stderr)
        return 3

    temp_file_path = ""
    try:
        # Rule #7: Use a safe, temporary directory for the downloaded file.
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as temp_file:
            temp_file_path = temp_file.name

        print(f"Downloading from {url} to {temp_file_path}")

        # Rules #1 & #2: The 'requests' library handles SSL/TLS validation by default.
        # Rule #9: Handle exceptions properly.
        # Rule #5: Streaming download prevents loading the whole file into memory.
        with requests.get(url, stream=True, timeout=30) as r:
            r.raise_for_status()  # Raises an HTTPError for bad responses
            with open(temp_file_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
        
        # Rule #8: On POSIX systems, set permissions to be executable only by the user.
        if os.name != 'nt':
            os.chmod(temp_file_path, 0o700)

        print(f"Executing {temp_file_path}")
        
        # Rule #4: Use subprocess.run for safer process creation.
        result = subprocess.run([temp_file_path], capture_output=True, text=True, check=False)

        print("Program finished with exit code:", result.returncode)
        if result.stdout:
            print("STDOUT:\n", result.stdout)
        if result.stderr:
            print("STDERR:\n", result.stderr, file=sys.stderr)

        return 0 # Success

    except requests.exceptions.RequestException as e:
        print(f"Error during download: {e}", file=sys.stderr)
        return 4
    except (subprocess.SubprocessError, OSError) as e:
        print(f"Error during execution: {e}", file=sys.stderr)
        return 5
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        return 6
    finally:
        # Cleanup: Delete the downloaded file.
        if temp_file_path and os.path.exists(temp_file_path):
            try:
                os.remove(temp_file_path)
                print(f"Cleaned up temporary file: {temp_file_path}")
            except OSError as e:
                print(f"Error cleaning up temporary file: {e}", file=sys.stderr)


if __name__ == '__main__':
    print("--- Running Test Cases ---")
    
    # Test Case 1: Valid URL
    print("\n[Test Case 1: Valid URL]")
    valid_url = "https://www.chiark.greenend.org.uk/~sgtatham/putty/latest/w64/putty.exe"
    result1 = download_and_execute(valid_url)
    print(f"Test Case 1 Result: {'Success (as expected)' if result1 == 0 else f'Failure (Code: {result1})'}")

    # Test Case 2: Invalid scheme (HTTP)
    print("\n[Test Case 2: HTTP URL]")
    http_url = "http://www.chiark.greenend.org.uk/~sgtatham/putty/latest/w64/putty.exe"
    result2 = download_and_execute(http_url)
    print(f"Test Case 2 Result: {'Failure (as expected)' if result2 != 0 else 'Success (unexpected)'}")

    # Test Case 3: Not an EXE file
    print("\n[Test Case 3: Non-EXE URL]")
    non_exe_url = "https://www.google.com/index.html"
    result3 = download_and_execute(non_exe_url)
    print(f"Test Case 3 Result: {'Failure (as expected)' if result3 != 0 else 'Success (unexpected)'}")

    # Test Case 4: Not Found URL
    print("\n[Test Case 4: Not Found URL]")
    not_found_url = "https://example.com/nonexistent/program.exe"
    result4 = download_and_execute(not_found_url)
    print(f"Test Case 4 Result: {'Failure (as expected)' if result4 != 0 else 'Success (unexpected)'}")

    # Test Case 5: None input
    print("\n[Test Case 5: None URL]")
    result5 = download_and_execute(None)
    print(f"Test Case 5 Result: {'Failure (as expected)' if result5 != 0 else 'Success (unexpected)'}")

    print("\n--- Test Cases Finished ---")