import requests
import os
import subprocess
import tempfile
import sys

# In Python, a class is not strictly necessary for this task structure.
# We will use a main class `Task86` with a static method to hold the tests.
class Task86:
    @staticmethod
    def download_and_execute(url):
        """
        Downloads an EXE file from a URL and executes it.
        WARNING: This is an inherently dangerous operation. Executing code from
        untrusted sources can compromise your system. This function should only be
        used with URLs from trusted and verified sources. A production system
        should include additional security measures like digital signature verification
        and sandboxing.
        """
        temp_file_path = None
        try:
            # 1. URL Validation and Download
            print(f"Downloading from: {url}")
            # Use a timeout for network requests and verify SSL certificates.
            with requests.get(url, stream=True, timeout=30, allow_redirects=True, verify=True) as response:
                response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)

                # 2. Download to a secure temporary file
                # Create a temporary file that is not deleted on close, so we can execute it.
                # We must handle deletion manually in a finally block.
                with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as temp_file:
                    temp_file_path = temp_file.name
                    for chunk in response.iter_content(chunk_size=8192):
                        temp_file.write(chunk)
            
            print(f"Downloaded to: {temp_file_path}")

            # On non-Windows systems, set execute permission
            if sys.platform != "win32":
                os.chmod(temp_file_path, 0o755)

            # 3. Execute the file
            print(f"Executing: {temp_file_path}")
            # Using Popen to launch the process without blocking.
            # This is safe from shell injection as arguments are passed as a list.
            process = subprocess.Popen([temp_file_path])
            
            # Optional: wait for completion
            # process.wait()
            # print(f"Execution finished with return code: {process.returncode}")

        except requests.exceptions.RequestException as e:
            print(f"Error during download: {e}", file=sys.stderr)
        except Exception as e:
            print(f"An error occurred: {e}", file=sys.stderr)
        finally:
            # 4. Cleanup
            if temp_file_path and os.path.exists(temp_file_path):
                try:
                    # On Windows, deletion might fail if the launched process is still running.
                    os.remove(temp_file_path)
                    print(f"Cleaned up temporary file: {temp_file_path}")
                except OSError as e:
                    print(f"Error cleaning up temporary file {temp_file_path}: {e}", file=sys.stderr)
    
    @staticmethod
    def main():
        print("--- Test Case 1: Valid Harmless EXE (PuTTY) ---")
        # WARNING: This URL points to a legitimate third-party application.
        # Running it is at your own risk. This test is for demonstration only.
        Task86.download_and_execute("https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe")

        print("\n--- Test Case 2: URL with 404 Not Found ---")
        Task86.download_and_execute("https://example.com/nonexistent/program.exe")

        print("\n--- Test Case 3: URL to a non-EXE file (text file) ---")
        # This will download a text file and attempt to execute it.
        # The operating system should handle this gracefully (e.g., show an error).
        Task86.download_and_execute("https://raw.githubusercontent.com/octocat/Spoon-Knife/main/README.md")

        print("\n--- Test Case 4: Invalid URL format ---")
        Task86.download_and_execute("ftp://invalid-url-format.com/file.exe") # requests will raise an InvalidSchema error
        
        print("\n--- Test Case 5: Another valid EXE (PSCP) ---")
        # PSCP is a command-line tool, it will run and exit quickly.
        Task86.download_and_execute("https://the.earth.li/~sgtatham/putty/latest/w64/pscp.exe")

if __name__ == "__main__":
    Task86.main()