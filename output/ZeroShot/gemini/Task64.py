import json
import sys
from urllib.request import urlopen, Request
from urllib.parse import urlparse
from urllib.error import URLError, HTTPError

# Constants for security
CONNECT_TIMEOUT = 5  # 5 seconds
MAX_RESPONSE_SIZE = 1024 * 1024  # 1 MB

def fetch_and_parse_json(url_string: str):
    """
    Fetches content from a URL, parses it as JSON, and returns the result.

    :param url_string: The URL to fetch the JSON from.
    :return: A Python object (dict or list) representing the JSON.
    :raises ValueError: For invalid URL protocols, response too large, or JSON parsing errors.
    :raises URLError: For network-related errors.
    """
    # 1. Security: Validate URL protocol to prevent Server-Side Request Forgery (SSRF)
    parsed_url = urlparse(url_string)
    if parsed_url.scheme not in ['http', 'https']:
        raise ValueError(f"Invalid protocol: '{parsed_url.scheme}'. Only HTTP and HTTPS are allowed.")

    # Set a user-agent to avoid being blocked by some services
    headers = {'User-Agent': 'Mozilla/5.0'}
    req = Request(url_string, headers=headers)

    try:
        # 2. Security: Use a timeout to prevent DoS attacks from slow servers
        with urlopen(req, timeout=CONNECT_TIMEOUT) as response:
            if response.status != 200:
                raise HTTPError(url_string, response.status, f"HTTP request failed with status code: {response.status}", response.headers, None)

            # 3. Security: Limit response size to prevent OutOfMemoryError (DoS vector)
            content_bytes = response.read(MAX_RESPONSE_SIZE + 1)
            if len(content_bytes) > MAX_RESPONSE_SIZE:
                raise ValueError(f"Response size exceeds the limit of {MAX_RESPONSE_SIZE} bytes.")
            
            # Decode assuming UTF-8, the standard for JSON
            json_string = content_bytes.decode('utf-8')

            # 4. Parse JSON
            return json.loads(json_string)

    except json.JSONDecodeError as e:
        raise ValueError(f"Failed to parse JSON content: {e}")
    except (URLError, HTTPError) as e:
        # Re-raise to be handled by the caller
        raise e

def main():
    test_urls = [
        "https://jsonplaceholder.typicode.com/posts/1",      # Test 1: Success, single object
        "https://jsonplaceholder.typicode.com/posts",         # Test 2: Success, array of objects
        "https://jsonplaceholder.typicode.com/posts/999999",  # Test 3: Client Error (404)
        "https://nonexistent-domain-for-testing123.com",     # Test 4: Network Error
        "https://www.google.com",                             # Test 5: JSON Parse Error
        "file:///etc/hosts"                                   # Test 6: Security Error (Invalid Protocol)
    ]

    for i, url in enumerate(test_urls):
        print(f"--- Test Case {i + 1}: {url} ---")
        try:
            json_object = fetch_and_parse_json(url)
            print("Success! Parsed JSON object (first 200 chars):")
            # Pretty print for better readability, but truncate for large results
            pretty_json = json.dumps(json_object, indent=2)
            print(pretty_json[:200] + ('...' if len(pretty_json) > 200 else ''))
        except Exception as e:
            print(f"Failed: {type(e).__name__} - {e}", file=sys.stderr)
        print()

if __name__ == "__main__":
    main()