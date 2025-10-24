
#!/usr/bin/env python3
"""\nSecure HTTPS web page title extractor.\nFetches content from an HTTPS URL and extracts the page title.\n"""

import sys
import re
import urllib.parse
import urllib.request
import ssl
from typing import Optional


def validate_url(url: str) -> bool:
    """\n    Validate that the URL is well-formed and uses HTTPS protocol.\n    \n    Args:\n        url: The URL string to validate\n        \n    Returns:\n        True if valid HTTPS URL, False otherwise\n    """
    # Check basic length constraints to prevent excessive memory usage
    if not url or len(url) > 2048:
        return False
    
    # Parse URL to validate structure
    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError:
        return False
    
    # Only allow HTTPS scheme for security
    if parsed.scheme != 'https':
        return False
    
    # Ensure netloc (hostname) is present and reasonable
    if not parsed.netloc or len(parsed.netloc) > 253:
        return False
    
    return True
def extract_title(html_content: str) -> Optional[str]:
    """
    Extract the title from HTML content using safe regex parsing.

    Args:
        html_content: The HTML content as a string

    Returns:
        The extracted title or None if not found
    """
    # Limit HTML content size to prevent excessive memory usage
    max_html_size = 10 * 1024 * 1024  # 10 MB limit
    if len(html_content) > max_html_size:
        html_content = html_content[:max_html_size]

    # Use regex to find title tag (case-insensitive, with multiline support)
    # This is a safe operation as we're only reading, not executing
    title_pattern = re.compile(r'<title[^>]*>(.*?)</title>', re.IGNORECASE | re.DOTALL)
    match = title_pattern.search(html_content)

    if match:
        title = match.group(1)
        # Strip whitespace and decode HTML entities safely
        title = title.strip()
        # Limit title length to prevent excessive output
        if len(title) > 1000:
            title = title[:1000]
        return title

    return None


def fetch_page_title(url: str) -> str:
    """
    Fetch a webpage via HTTPS and extract its title.

    Args:
        url: The HTTPS URL to fetch

    Returns:
        The page title or an error message
    """
    # Validate URL before making any network request
    if not validate_url(url):
        return "Error: Invalid URL. Only HTTPS URLs are allowed and must be well-formed."

    try:
        # Create SSL context with certificate verification enabled
        # This ensures proper SSL/TLS certificate validation (CWE-295, CWE-297)
        ssl_context = ssl.create_default_context()
        # Enforce hostname verification
        ssl_context.check_hostname = True
        # Require certificate verification
        ssl_context.verify_mode = ssl.CERT_REQUIRED

        # Set a reasonable timeout to prevent indefinite hangs
        timeout = 30  # seconds

        # Create request with User-Agent to avoid being blocked by some servers
        headers = {
            'User-Agent': 'Mozilla/5.0 (compatible; SecurePageTitleExtractor/1.0)'
        }
        request = urllib.request.Request(url, headers=headers)

        # Make HTTPS request with SSL context and timeout
        with urllib.request.urlopen(request, context=ssl_context, timeout=timeout) as response:
            # Check response status
            if response.status != 200:
                return f"Error: HTTP status {response.status}"

            # Limit response size to prevent excessive memory usage
            max_response_size = 10 * 1024 * 1024  # 10 MB
            content = response.read(max_response_size)

            # Decode content safely
            # Try to get charset from Content-Type header
            content_type = response.headers.get('Content-Type', '')
            encoding = 'utf-8'  # default

            if 'charset=' in content_type:
                try:
                    encoding = content_type.split('charset=')[-1].split(';')[0].strip()
                except (IndexError, AttributeError):
                    encoding = 'utf-8'

            # Decode with error handling
            try:
                html_content = content.decode(encoding, errors='replace')
            except (UnicodeDecodeError, LookupError):
                html_content = content.decode('utf-8', errors='replace')

            # Extract and return title
            title = extract_title(html_content)
            if title:
                return title
            else:
                return "Error: No title found in HTML content"

    except ssl.SSLError as e:
        # SSL/TLS certificate validation failed
        return f"Error: SSL certificate validation failed: {str(e)}"
    except urllib.error.HTTPError as e:
        # HTTP error (4xx, 5xx)
        return f"Error: HTTP error {e.code}: {e.reason}"
    except urllib.error.URLError as e:
        # Network error or invalid URL
        return f"Error: Network error: {str(e.reason)}"
    except TimeoutError:
        return "Error: Request timed out"
    except Exception as e:
        # Catch any other unexpected errors
        return f"Error: Unexpected error: {str(type(e).__name__)}"


def main() -> int:
    """\n    Main entry point for the program.\n    \n    Returns:\n        Exit code (0 for success, 1 for error)\n    """
    # Validate command line arguments
    if len(sys.argv) != 2:
        print("Usage: python solution.py <HTTPS_URL>", file=sys.stderr)
        print("Example: python solution.py https://www.example.com", file=sys.stderr)
        return 1
    
    # Get URL from command line argument (treating it as untrusted input)
    url = sys.argv[1]
    
    # Validate input length
    if len(url) > 2048:
        print("Error: URL too long (max 2048 characters)", file=sys.stderr)
        return 1
    
    # Fetch and print the page title
    result = fetch_page_title(url)
    print(result)
    
    # Return success if no error message
    return 0 if not result.startswith("Error:") else 1


# Test cases
if __name__ == "__main__":
    # Check if running in test mode
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print("Running test cases...")
        print()
        
        # Test case 1: Valid HTTPS URL (example.com)
        print("Test 1: Valid HTTPS URL")
        test_url_1 = "https://www.example.com"
        result_1 = fetch_page_title(test_url_1)
        print(f"URL: {test_url_1}")
        print(f"Result: {result_1}")
        print()
        
        # Test case 2: Invalid protocol (HTTP instead of HTTPS)
        print("Test 2: Invalid protocol (HTTP)")
        test_url_2 = "http://www.example.com"
        result_2 = fetch_page_title(test_url_2)
        print(f"URL: {test_url_2}")
        print(f"Result: {result_2}")
        print()
        
        # Test case 3: Malformed URL
        print("Test 3: Malformed URL")
        test_url_3 = "not_a_valid_url"
        result_3 = fetch_page_title(test_url_3)
        print(f"URL: {test_url_3}")
        print(f"Result: {result_3}")
        print()
        
        # Test case 4: Empty string
        print("Test 4: Empty string")
        test_url_4 = ""
        result_4 = fetch_page_title(test_url_4)
        print(f"URL: (empty)")
        print(f"Result: {result_4}")
        print()
        
        # Test case 5: URL too long
        print("Test 5: URL too long")
        test_url_5 = "https://example.com/" + "a" * 3000
        result_5 = fetch_page_title(test_url_5)
        print(f"URL: (very long URL)")
        print(f"Result: {result_5}")
        print()
        
        sys.exit(0)
    else:
        sys.exit(main())
