
#!/usr/bin/env python3
"""\nSecure JSON fetcher from URL with comprehensive input validation.\nImplements all security requirements including input validation, secure network access,\nand proper error handling.\n"""

import sys
import json
import urllib.request
import urllib.error
import ssl
from typing import Any, Dict, Optional
from urllib.parse import urlparse


# Constants for security limits
MAX_URL_LENGTH = 2048  # Prevent excessive URL lengths
MAX_RESPONSE_SIZE = 10 * 1024 * 1024  # 10MB limit to prevent memory exhaustion
ALLOWED_SCHEMES = {'https'}  # Only allow HTTPS for security
TIMEOUT_SECONDS = 30  # Prevent indefinite hangs

def validate_url(url: str) -> bool:
    """
    Validate URL input against security requirements.

    Args:
        url: The URL string to validate

    Returns:
        True if valid, False otherwise

    Security: Treats input as untrusted, validates length, scheme, and format
    """
    # Check URL length to prevent buffer issues
    if not url or len(url) > MAX_URL_LENGTH:
        return False

    # Parse and validate URL structure
    try:
        parsed = urlparse(url)

        # Only allow HTTPS scheme for secure transmission
        if parsed.scheme not in ALLOWED_SCHEMES:
            return False

        # Ensure hostname exists and is not empty
        if not parsed.netloc:
            return False

        # Basic validation that hostname doesn't contain suspicious characters
        if any(char in parsed.netloc for char in [' ', '\n', '\r', '\t']):
            return False

        return True

    except (ValueError, AttributeError):
        # urlparse failed - invalid URL format
        return False


def create_secure_ssl_context() -> ssl.SSLContext:
    """
    Create a secure SSL context with proper certificate verification.

    Returns:
        Configured SSL context

    Security: Implements certificate validation, hostname verification,
    and uses secure protocol versions
    """
    # Create SSL context with secure defaults
    context = ssl.create_default_context()

    # Ensure certificate verification is enabled (Rules#3)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    # Use only secure protocol versions (TLSv1.2+)
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    return context


def fetch_json_from_url(url: str) -> Optional[Dict[str, Any]]:
    """
    Fetch and parse JSON from a URL with comprehensive security measures.

    Args:
        url: The HTTPS URL to fetch JSON from

    Returns:
        Parsed JSON object as dictionary, or None on error

    Security: Validates all inputs, uses secure SSL/TLS, prevents resource exhaustion,
    handles all exceptions, and validates JSON parsing
    """
    # Rule#5: Validate input before processing
    if not validate_url(url):
        print(
            "Error: Invalid URL format or insecure scheme. Only HTTPS URLs are allowed.",
            file=sys.stderr,
        )
        return None

    try:
        # Rule#3 & #4: Create secure SSL context with certificate and hostname verification
        ssl_context = create_secure_ssl_context()

        # Create request with security headers
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": "SecureJSONFetcher/1.0",
                "Accept": "application/json",
            },
        )

        # Rule#6: Open connection with timeout to prevent indefinite hangs
        # Use context manager for automatic resource cleanup (Rule#8)
        with urllib.request.urlopen(
                request,
                timeout=TIMEOUT_SECONDS,
                context=ssl_context,
        ) as response:
            # Validate response content type
            content_type = response.headers.get("Content-Type", "")
            if "application/json" not in content_type.lower():
                print(f"Warning: Unexpected content type: {content_type}", file=sys.stderr)

            # Rule#6: Read response with size limit to prevent memory exhaustion
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > MAX_RESPONSE_SIZE:
                print(
                    f"Error: Response too large (>{MAX_RESPONSE_SIZE} bytes)",
                    file=sys.stderr,
                )
                return None

            # Read data in chunks with size validation
            data = b""
            chunk_size = 8192

            while True:
                chunk = response.read(chunk_size)
                if not chunk:
                    break

                # Enforce maximum size during reading
                if len(data) + len(chunk) > MAX_RESPONSE_SIZE:
                    print(
                        f"Error: Response exceeds maximum size of {MAX_RESPONSE_SIZE} bytes",
                        file=sys.stderr,
                    )
                    return None

                data += chunk

        # Rule#2: Use safe JSON parsing (no eval or exec)
        # Parse JSON with strict mode to prevent potential issues
        json_data = json.loads(data.decode("utf-8"))

        return json_data

    except urllib.error.HTTPError as e:
        # Rule#8: Handle HTTP errors appropriately
        print(f"HTTP Error {e.code}: {e.reason}", file=sys.stderr)
        return None

    except urllib.error.URLError as e:
        # Rule#8: Handle URL/network errors
        print(f"URL Error: {e.reason}", file=sys.stderr)
        return None

    except ssl.SSLError as e:
        # Rule#8: Handle SSL/TLS errors (certificate validation failures)
        print(f"SSL Error: {e}", file=sys.stderr)
        return None

    except json.JSONDecodeError as e:
        # Rule#8: Handle JSON parsing errors
        print(
            f"JSON Decode Error: {e.msg} at line {e.lineno}, column {e.colno}",
            file=sys.stderr,
        )
        return None

    except (UnicodeDecodeError, ValueError) as e:
        # Rule#8: Handle encoding and value errors
        print(f"Error processing response: {e}", file=sys.stderr)
        return None

    except Exception as e:
        # Rule#8: Catch any unexpected errors
        print(f"Unexpected error: {type(e).__name__}: {e}", file=sys.stderr)
        return None


def main() -> int:
    """
    Main entry point - processes command line arguments and fetches JSON.

    Returns:
        Exit code: 0 for success, 1 for error

    Security: Validates command line input, provides clear error messages
    """
    # Rule#5: Validate command line arguments
    if len(sys.argv) != 2:
        print("Usage: python task64.py <URL>", file=sys.stderr)
        print(
            "Example: python task64.py https://api.example.com/data.json",
            file=sys.stderr,
        )
        return 1

    url = sys.argv[1]

    # Fetch and parse JSON
    result = fetch_json_from_url(url)

    if result is not None:
        # Output the JSON in a readable format
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    else:
        return 1


if __name__ == "__main__":
    # Test cases for validation
    def run_tests() -> None:
        """Run test cases to verify functionality."""
        print("Running test cases...\n")

        # Test 1: Valid HTTPS URL format
        test_url_1 = "https://jsonplaceholder.typicode.com/posts/1"
        print(f"Test 1 - Valid HTTPS URL: {test_url_1}")
        result1 = fetch_json_from_url(test_url_1)
        print(f"Result: {'SUCCESS' if result1 else 'FAILED'}\n")

        # Test 2: Invalid scheme (HTTP instead of HTTPS)
        test_url_2 = "http://example.com/data.json"
        print(f"Test 2 - Invalid scheme (HTTP): {test_url_2}")
        result2 = fetch_json_from_url(test_url_2)
        print(f"Result: {'FAILED - should reject' if result2 else 'SUCCESS - rejected'}\n")

        # Test 3: Empty URL
        test_url_3 = ""
        print("Test 3 - Empty URL")
        result3 = fetch_json_from_url(test_url_3)
        print(f"Result: {'FAILED - should reject' if result3 else 'SUCCESS - rejected'}\n")

        # Test 4: URL too long
        test_url_4 = "https://example.com/" + "a" * 3000
        print("Test 4 - URL exceeds maximum length")
        result4 = fetch_json_from_url(test_url_4)
        print(f"Result: {'FAILED - should reject' if result4 else 'SUCCESS - rejected'}\n")

        # Test 5: Valid JSON array endpoint
        test_url_5 = "https://jsonplaceholder.typicode.com/users/1"
        print(f"Test 5 - Valid HTTPS URL (user data): {test_url_5}")
        result5 = fetch_json_from_url(test_url_5)
        print(f"Result: {'SUCCESS' if result5 else 'FAILED'}\n")

        print("Test execution completed.")

    # Uncomment to run tests instead of normal operation
    # run_tests()
    # sys.exit(0)

    sys.exit(main())
