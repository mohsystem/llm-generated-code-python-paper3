import urllib.request
import tempfile
import subprocess
import os
import sys

def download_and_execute(url):
    """
    WARNING: This function downloads and executes a file from the internet.
    This is an extremely dangerous operation and can expose your system to
    malware and other security risks. Only use this with URLs from sources
    you completely trust. The downloaded executable will have the same
    permissions as the user running this Python script.
    
    This implementation is primarily designed for Windows to execute .exe files.
    
    Args:
        url (str): The URL of the EXE file to download and execute.
        
    Returns:
        bool: True if the process was started successfully, False otherwise.
    """
    temp_file_path = ''
    try:
        # 1. Create a secure temporary file.
        # delete=False is crucial, so the file is not deleted when closed,
        # allowing us to execute it. We must handle deletion manually.
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as temp_file:
            temp_file_path = temp_file.name
            
            # 2. Download the file from the URL.
            print(f"Downloading from {url} to {temp_file_path}")
            with urllib.request.urlopen(url) as response:
                # Check for successful response
                if response.getcode() != 200:
                    print(f"Error: Download failed with HTTP status {response.getcode()}", file=sys.stderr)
                    return False
                
                # Write the content to the temporary file
                temp_file.write(response.read())

        # On non-Windows, we would need to make the file executable
        if os.name != 'nt':
            os.chmod(temp_file_path, 0o755)

        # 3. Execute the downloaded file.
        # Using a list for the command avoids shell injection vulnerabilities.
        print(f"Executing {temp_file_path}")
        # Use subprocess.Popen() for asynchronous execution.
        process = subprocess.Popen([temp_file_path])
        print(f"Process started successfully with PID: {process.pid}")
        return True

    except urllib.error.URLError as e:
        print(f"Error: Could not download from URL. Reason: {e.reason}", file=sys.stderr)
        return False
    except FileNotFoundError:
        print(f"Error: Temporary file not found at {temp_file_path}", file=sys.stderr)
        return False
    except OSError as e:
        # This can catch errors like "is not a valid Win32 application"
        print(f"Error: Failed to execute the file. Reason: {e}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        return False
    finally:
        # 4. Cleanup: Ensure the temporary file is deleted.
        if temp_file_path and os.path.exists(temp_file_path):
            try:
                os.remove(temp_file_path)
                print(f"Cleaned up temporary file: {temp_file_path}")
            except OSError as e:
                print(f"Error cleaning up temporary file: {e}", file=sys.stderr)

if __name__ == "__main__":
    print("--- Running Test Cases ---")

    # Test Case 1: A well-known, safe 64-bit executable (PuTTY)
    print("\n--- Test Case 1: Valid 64-bit EXE (PuTTY) ---")
    download_and_execute("https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe")

    # Test Case 2: A well-known, safe portable executable (Process Explorer)
    print("\n--- Test Case 2: Valid portable EXE (Process Explorer) ---")
    download_and_execute("https://live.sysinternals.com/procexp.exe")

    # Test Case 3: An invalid URL that will fail to download
    print("\n--- Test Case 3: Invalid URL ---")
    download_and_execute("https://this-is-a-fake-url-12345.com/nonexistent.exe")
    
    # Test Case 4: A valid URL to a non-executable file
    print("\n--- Test Case 4: Valid URL, but not an EXE ---")
    download_and_execute("https://www.google.com/images/branding/googlelogo/1x/googlelogo_color_272x92dp.png")

    # Test Case 5: A well-known, safe 32-bit executable (PuTTY)
    print("\n--- Test Case 5: Valid 32-bit EXE (PuTTY) ---")
    download_and_execute("https://the.earth.li/~sgtatham/putty/latest/w32/putty.exe")