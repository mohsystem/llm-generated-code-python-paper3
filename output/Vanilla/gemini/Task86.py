import urllib.request
import subprocess
import os
import sys

# WARNING: Downloading and executing files from the internet can be extremely dangerous.
# Only run this with URLs from trusted sources.

def download_and_execute(url, file_name):
    """
    Downloads an executable file from a URL and runs it.
    :param url: The URL of the EXE file.
    :param file_name: The local filename to save the EXE as.
    """
    try:
        # Step 1: Download the file
        print(f"Downloading {url} to {file_name}...")
        urllib.request.urlretrieve(url, file_name)
        print("Download complete.")
        
        full_path = os.path.abspath(file_name)

        # On non-Windows OS, we need to make the file executable
        if sys.platform != "win32":
            os.chmod(full_path, 0o755)

        # Step 2: Execute the downloaded file
        print(f"Executing {full_path}...")
        # Popen starts the process. We then wait for it to complete.
        process = subprocess.Popen([full_path])
        process.wait()
        print(f"'{file_name}' finished with exit code: {process.returncode}")

    except Exception as e:
        print(f"An error occurred: {e}", file=sys.stderr)

def main():
    """ Main function to run test cases """
    # Using a URL for a safe, well-known executable (PuTTY)
    file_url = "https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe"
    
    print("--- Starting 5 Test Cases ---")

    print("\n--- Test Case 1 ---")
    download_and_execute(file_url, "putty_python_1.exe")

    print("\n--- Test Case 2 ---")
    download_and_execute(file_url, "putty_python_2.exe")
    
    print("\n--- Test Case 3 ---")
    download_and_execute(file_url, "putty_python_3.exe")
    
    print("\n--- Test Case 4 ---")
    download_and_execute(file_url, "putty_python_4.exe")
    
    print("\n--- Test Case 5 ---")
    download_and_execute(file_url, "putty_python_5.exe")
    
    print("\n--- All tests completed ---")

if __name__ == "__main__":
    main()