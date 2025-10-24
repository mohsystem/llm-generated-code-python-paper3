import os
import subprocess
import tempfile
import requests
from urllib.parse import urlparse
import typing

# Rule #3: Define a strict allowlist of domains to download from.
# Google Drive web links may redirect to googleusercontent.com for content.
ALLOWED_DOMAINS: typing.List[str] = [
    "drive.google.com",
    "googleusercontent.com",
]

def is_allowed_domain(hostname: str) -> bool:
    """
    Checks if the hostname is an exact match or a valid subdomain of the allowed domains.
    """
    if not hostname:
        return False
    
    # Normalize by removing any trailing dot.
    hostname = hostname.rstrip('.')
    
    for domain in ALLOWED_DOMAINS:
        if hostname == domain or hostname.endswith(f'.{domain}'):
            return True
            
    return False

def validate_initial_url(url: str) -> bool:
    """
    Performs strict validation on the user-provided initial URL.
    This includes checking for the .exe extension.
    """
    if not isinstance(url, str) or not url:
        print("Error: URL must be a non-empty string.")
        return False
        
    try:
        parsed_url = urlparse(url)
        
        # Rule #1, #2: Enforce HTTPS
        if parsed_url.scheme != 'https':
            print("Error: URL must use the https scheme.")
            return False
        
        hostname = parsed_url.hostname
        if not hostname:
            print("Error: URL is missing a valid hostname.")
            return False

        if not is_allowed_domain(hostname):
            print(f"Error: Domain '{hostname}' is not in the allowed list.")
            return False

        # Rule #3: Enforce expected file type in path for initial URL
        if not parsed_url.path.lower().endswith('.exe'):
            print("Error: Initial URL must point to a file with a .exe extension.")
            return False
            
    except (ValueError, AttributeError):
        print(f"Error: The provided URL '{url}' is malformed.")
        return False
        
    return True
    
def download_file(url: str, dest_path: str) -> bool:
    """
    Downloads a file from a URL, securely validating the entire redirect chain.
    """
    try:
        # Rule #1, #2: `requests` handles SSL/TLS cert and hostname validation by default.
        # We explicitly do not disable it (verify=True is default).
        # A reasonable timeout prevents the application from hanging.
        with requests.get(url, stream=True, timeout=60, allow_redirects=True) as response:
            
            # Security check: Validate every URL in the redirect chain.
            all_urls_in_chain = [r.url for r in response.history] + [response.url]
            for u in all_urls_in_chain:
                parsed_u = urlparse(u)
                if parsed_u.scheme != 'https':
                    print(f"Error: Aborting due to insecure (non-https) redirect to '{u}'.")
                    return False
                if not parsed_u.hostname or not is_allowed_domain(parsed_u.hostname):
                    print(f"Error: Aborting due to redirect to a disallowed domain '{parsed_u.hostname}'.")
                    return False
            
            # Raise an exception for HTTP error codes (4xx or 5xx).
            response.raise_for_status()
            
            # Rule #5: Stream the download to avoid high memory usage for large files.
            with open(dest_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
                    
        print(f"Successfully downloaded file to '{dest_path}'")
        return True
    except requests.exceptions.RequestException as e:
        print(f"Error during download: {e}")
        return False
    except IOError as e:
        print(f"Error writing file to '{dest_path}': {e}")
        return False

def execute_file(file_path: str) -> bool:
    """
    Executes a local file securely.
    """
    # Rule #7: The file path is from `tempfile`, which is a safe, non-predictable location.
    if not os.path.isfile(file_path):
        print(f"Error: File to execute does not exist at '{file_path}'.")
        return False

    try:
        print(f"Executing '{file_path}'...")
        # Rule #4: Use subprocess.run with a list of arguments to prevent shell injection.
        # `check=True` raises an error if the process returns a non-zero exit code.
        result = subprocess.run(
            [file_path],
            check=True,
            capture_output=True,
            text=True,
            timeout=300  # 5-minute timeout for the executed process.
        )
        print("Execution completed successfully.")
        if result.stdout:
            print(f"STDOUT:\n{result.stdout}")
        if result.stderr:
            print(f"STDERR:\n{result.stderr}")
        return True
    except FileNotFoundError:
        print(f"Error: Command not found at '{file_path}'.")
        return False
    except subprocess.CalledProcessError as e:
        print(f"Execution failed with return code {e.returncode}.")
        if e.stdout:
            print(f"STDOUT:\n{e.stdout}")
        if e.stderr:
            print(f"STDERR:\n{e.stderr}")
        return False
    except subprocess.TimeoutExpired:
        print("Execution timed out after 300 seconds.")
        return False
    except PermissionError:
        print(f"Error: Permission denied to execute '{file_path}'.")
        return False

def download_and_execute_from_url(url: str) -> None:
    """
    Orchestrates the download and execution of a program from a URL.
    """
    # Rule #3: Validate all user input before processing.
    if not validate_initial_url(url):
        return

    temp_file_path = ''
    try:
        # Rule #8: Use a secure temporary file.
        # `delete=False` is needed on Windows, as a file cannot be executed while open.
        # We manually handle the cleanup in the `finally` block.
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as temp_f:
            temp_file_path = temp_f.name
        
        print(f"Created temporary file at '{temp_file_path}'")

        if download_file(url, temp_file_path):
            execute_file(temp_file_path)

    finally:
        # Ensure the temporary file is always cleaned up.
        if temp_file_path and os.path.exists(temp_file_path):
            try:
                os.remove(temp_file_path)
                print(f"Cleaned up temporary file '{temp_file_path}'")
            except OSError as e:
                print(f"Error during cleanup of temporary file '{temp_file_path}': {e}")


def main():
    """
    Main function containing test cases.
    Note: These URLs are for testing validation logic only and are not real.
    The download step is expected to fail for these test cases.
    """
    test_cases = [
        # 1. Valid-looking Google Drive URL
        "https://drive.google.com/uc?export=download&id=FAKE_ID_123.exe",
        # 2. Valid-looking googleusercontent URL
        "https://lh3.googleusercontent.com/d/FAKE_ID_XYZ.exe",
        # 3. Invalid: HTTP scheme
        "http://drive.google.com/some/path/program.exe",
        # 4. Invalid: Disallowed domain
        "https://malicious-site.com/program.exe",
        # 5. Invalid: Path does not end with .exe
        "https://drive.google.com/uc?id=document.zip",
    ]

    for i, url in enumerate(test_cases, 1):
        print(f"\n--- Test Case {i}: Testing URL '{url}' ---")
        download_and_execute_from_url(url)
        print("--- End Test Case ---")

if __name__ == "__main__":
    main()