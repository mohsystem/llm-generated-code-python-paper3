import requests
from urllib.parse import urlparse
import sys

# Define constants for security and resource management
MAX_RESPONSE_SIZE = 1024 * 1024  # 1 MB
REQUEST_TIMEOUT = 5  # 5 seconds

def is_valid_url(url: str) -> bool:
    """
    Validates if a URL has a valid format and an allowed scheme (http/https).

    Args:
        url: The URL string to validate.

    Returns:
        True if the URL is valid, False otherwise.
    """
    if not isinstance(url, str):
        return False
    try:
        # Rule #3: Validate input according to expected formats.
        # urlparse is a robust way to check URL structure.
        result = urlparse(url)
        # We explicitly check for http/https schemes to prevent requests
        # to local files (file://) or other potentially dangerous schemes.
        return all([result.scheme in ['http', 'https'], result.netloc])
    except (ValueError, AttributeError):
        return False

def make_http_request(url: str) -> str:
    """
    Accepts a URL, validates it, and makes a secure HTTP GET request.

    Args:
        url: The URL to fetch.

    Returns:
        The response body as a string on success, or an error message on failure.
    """
    # Rule #3: Ensure all input is validated before processing.
    if not is_valid_url(url):
        return "Error: Invalid URL format or scheme is not http/https."

    try:
        # Rule #4: Use potentially dangerous functions with caution.
        # We use a context manager for the request object.
        # Rules #1, #2: requests handles SSL/TLS cert and hostname validation by default.
        with requests.get(
            url,
            timeout=REQUEST_TIMEOUT,      # Prevents hanging (CWE-400)
            allow_redirects=False,    # Mitigates some SSRF risks
            stream=True               # Allows controlling memory usage (CWE-400)
        ) as response:
            # Check for HTTP client/server errors (4xx or 5xx status codes)
            response.raise_for_status()

            # Rule #5: Prevent excessive memory usage by checking Content-Length first.
            content_length_str = response.headers.get('Content-Length')
            if content_length_str and int(content_length_str) > MAX_RESPONSE_SIZE:
                return f"Error: Response size exceeds the limit of {MAX_RESPONSE_SIZE} bytes."

            # Rule #5: Read the response in chunks to adhere to buffer boundaries.
            content = b''
            for chunk in response.iter_content(chunk_size=8192):
                if len(content) + len(chunk) > MAX_RESPONSE_SIZE:
                    return f"Error: Response size exceeds the limit of {MAX_RESPONSE_SIZE} bytes."
                content += chunk

            # Decode using the encoding specified in headers, with a safe fallback.
            encoding = response.encoding or 'utf-8'
            return content.decode(encoding, errors='replace')

    except requests.exceptions.Timeout:
        return f"Error: Request timed out after {REQUEST_TIMEOUT} seconds."
    except requests.exceptions.SSLError as e:
        return f"Error: SSL certificate verification failed: {e}"
    except requests.exceptions.RequestException as e:
        return f"Error: An HTTP request error occurred: {e}"
    except Exception as e:
        return f"An unexpected error occurred: {e}"

def main():
    """
    Main function to run test cases for the HTTP request function.
    """
    test_cases = [
        "https://www.example.com",
        "http://httpbin.org/get",
        "not-a-valid-url",
        "ftp://ftp.example.org",
        "https://this-domain-likely-does-not-exist-asdfghjkl.com"
    ]

    print("--- Running Test Cases ---")
    for i, url in enumerate(test_cases, 1):
        print(f"\n--- Test Case {i}: Requesting URL: {url} ---")
        result = make_http_request(url)
        
        # To keep output clean, truncate long successful responses.
        if not result.startswith("Error:"):
            print(f"Response (first 200 chars):\n{result[:200]}...")
        else:
            print(result)

if __name__ == "__main__":
    # Example of how to take a URL from a user (command-line argument)
    if len(sys.argv) > 1:
        user_url = sys.argv[1]
        print(f"\n--- Running with user-provided URL: {user_url} ---")
        print(make_http_request(user_url))
    else:
        main()