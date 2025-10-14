import os
import re
import urllib.parse
import urllib.request
import ssl
import tempfile
import shutil
from pathlib import Path
from typing import Optional

BASE_DIRECTORY = "/var/app/safe_files"
ALLOWED_EXTENSIONS = {".txt", ".pdf", ".jpg", ".png"}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB


def retrieve_file_from_server(server_url: str, file_name: str) -> str:
    """
    Retrieve a file from a server and save it securely.

    Args:
        server_url: Base URL of the server (must be HTTPS)
        file_name: Name of the file to retrieve

    Returns:
        Status message indicating success or error
    """
    if not server_url or not server_url.strip():
        return "Error: Server URL cannot be null or empty"
    if not file_name or not file_name.strip():
        return "Error: File name cannot be null or empty"

    # Validate and sanitize file name
    sanitized_file_name = sanitize_file_name(file_name)
    if sanitized_file_name is None:
        return "Error: Invalid file name"

    # Validate server URL
    if not is_valid_url(server_url):
        return "Error: Invalid server URL"

    # Construct safe file path
    try:
        base_path = Path(BASE_DIRECTORY).resolve()
        target_path = (base_path / sanitized_file_name).resolve()

        # Prevent path traversal
        if not str(target_path).startswith(str(base_path)):
            return "Error: Path traversal attempt detected"

        # Validate file extension
        if not has_allowed_extension(sanitized_file_name):
            return "Error: File type not allowed"

        # Create base directory if it doesn't exist
        base_path.mkdir(parents=True, exist_ok=True)

        # Construct full URL
        encoded_file_name = urllib.parse.quote(sanitized_file_name)
        full_url = f"{server_url}/{encoded_file_name}"

        # Parse URL to ensure HTTPS
        parsed_url = urllib.parse.urlparse(full_url)
        if parsed_url.scheme != "https":
            return "Error: Only HTTPS connections are allowed"

        # Create SSL context with certificate verification
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = True
        ssl_context.verify_mode = ssl.CERT_REQUIRED

        # Create request
        request = urllib.request.Request(full_url, method="GET")

        # Download file
        with urllib.request.urlopen(request, timeout=10, context=ssl_context) as response:
            if response.status != 200:
                return f"Error: Server returned status code {response.status}"

            content_length = response.getheader("Content-Length")
            if content_length and int(content_length) > MAX_FILE_SIZE:
                return "Error: File size exceeds maximum allowed size"

            # Write to temporary file first
            with tempfile.NamedTemporaryFile(dir=base_path, delete=False, suffix=".download") as temp_file:
                temp_path = temp_file.name
                total_bytes_read = 0

                while True:
                    chunk = response.read(8192)
                    if not chunk:
                        break

                    total_bytes_read += len(chunk)
                    if total_bytes_read > MAX_FILE_SIZE:
                        os.unlink(temp_path)
                        return "Error: File size exceeds maximum allowed size"

                    temp_file.write(chunk)

            # Atomic move to final location
            shutil.move(temp_path, target_path)

            return f"Success: File retrieved and saved to {target_path}"

    except urllib.error.URLError as e:
        return f"Error: Failed to retrieve file - {str(e)}"
    except Exception as e:
        return f"Error: {str(e)}"


def sanitize_file_name(file_name: str) -> Optional[str]:
    """Sanitize and validate file name."""
    if not file_name:
        return None

    # Remove path separators and null bytes
    sanitized = re.sub(r'[/\\\x00]', '', file_name)

    # Remove leading/trailing dots and spaces
    sanitized = sanitized.strip().lstrip('.')

    # Check for valid characters only
    if not re.match(r'^[a-zA-Z0-9._-]+$', sanitized):
        return None

    # Limit length
    if len(sanitized) > 255:
        return None

    return sanitized


def has_allowed_extension(file_name: str) -> bool:
    """Check if file has an allowed extension."""
    lower_file_name = file_name.lower()
    return any(lower_file_name.endswith(ext) for ext in ALLOWED_EXTENSIONS)


def is_valid_url(url_string: str) -> bool:
    """Validate URL format and protocol."""
    try:
        parsed = urllib.parse.urlparse(url_string)
        if parsed.scheme != "https":
            return False
        if not parsed.netloc:
            return False
        return True
    except Exception:
        return False


def main():
    print("Test Case 1: Valid HTTPS URL and file name")
    print(retrieve_file_from_server("https://example.com/files", "document.txt"))

    print("\nTest Case 2: Path traversal attempt")
    print(retrieve_file_from_server("https://example.com/files", "../../../etc/passwd"))

    print("\nTest Case 3: Invalid file extension")
    print(retrieve_file_from_server("https://example.com/files", "malware.exe"))

    print("\nTest Case 4: Invalid URL (HTTP instead of HTTPS)")
    print(retrieve_file_from_server("http://example.com/files", "document.txt"))

    print("\nTest Case 5: Null or empty inputs")
    print(retrieve_file_from_server("", "document.txt"))


if __name__ == "__main__":
    main()
