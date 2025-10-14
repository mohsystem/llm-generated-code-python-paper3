
import urllib.request
import os
import subprocess
import sys
import tempfile
import time

def download_and_execute(url):
    try:
        # Generate temporary file name
        temp_dir = tempfile.gettempdir()
        file_name = f"downloaded_{int(time.time() * 1000)}.exe"
        file_path = os.path.join(temp_dir, file_name)
        
        # Download file
        urllib.request.urlretrieve(url, file_path)
        
        # Make file executable (Unix-like systems)
        if sys.platform != 'win32':
            os.chmod(file_path, 0o755)
        
        # Execute the file
        if sys.platform == 'win32':
            process = subprocess.Popen([file_path])
        else:
            process = subprocess.Popen([file_path])
        
        # Wait for process with timeout
        try:
            process.wait(timeout=30)
            execution_status = "completed"
        except subprocess.TimeoutExpired:
            process.kill()
            execution_status = "timed out"
        
        result = f"File downloaded to: {file_path}\\nExecution {execution_status}"
        return result
        
    except Exception as e:
        return f"Error: {str(e)}"

if __name__ == "__main__":
    print("=== SECURITY WARNING: This program downloads and executes files ===\\n")
    
    # Test cases - Using safe/mock URLs
    test_urls = [
        "https://example.com/safe-program.exe",
        "https://example.com/test-app.exe",
        "https://example.com/utility.exe",
        "https://example.com/installer.exe",
        "https://example.com/application.exe"
    ]
    
    for i, url in enumerate(test_urls, 1):
        print(f"Test Case {i}:")
        print(f"URL: {url}")
        print(f"Result: {download_and_execute(url)}")
        print("---")
