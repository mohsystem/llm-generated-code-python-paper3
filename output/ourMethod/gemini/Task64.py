import sys
import json
import requests
from typing import Dict, Any

# This script requires the 'requests' library.
# Install it using pip:
# pip install requests

def fetch_and_parse_json(url: str) -> Dict[str, Any]:
    """
    Fetches a JSON file from a URL, parses it, and returns the resulting dictionary.

    Args:
        url: The URL of the JSON file.

    Returns:
        A dictionary representing the JSON object.

    Raises:
        ValueError: If the URL is invalid or the scheme is not https.
        requests.exceptions.RequestException: For network-related errors.
        json.JSONDecodeError: If the response is not valid JSON.
    """
    if not isinstance(url, str) or not url.strip():
        raise ValueError("URL must be a non-empty string.")

    if not url.lower().startswith('https://'):
        raise ValueError("Invalid URL scheme. Only HTTPS is supported for security.")

    try:
        # Use a context manager to ensure the session is closed.
        with requests.Session() as session:
            # Set a timeout for the request to avoid hanging.
            # allow_redirects=False is a security measure to prevent open redirect vulnerabilities.
            with session.get(
                url, 
                timeout=(5, 10),  # (connect_timeout, read_timeout)
                allow_redirects=False, 
                headers={'Accept': 'application/json'}
            ) as response:
                # Raise an HTTPError for bad responses (4xx or 5xx)
                response.raise_for_status()
                
                # The .json() method will parse the JSON response content
                # and raise a json.JSONDecodeError if parsing fails.
                return response.json()

    except requests.exceptions.RequestException as e:
        # Catches connection errors, timeouts, HTTP errors, etc.
        raise requests.exceptions.RequestException(f"Network or HTTP error fetching URL: {e}")
    except json.JSONDecodeError as e:
        # Catches errors from parsing invalid JSON.
        raise json.JSONDecodeError(f"Failed to parse JSON response: {e.msg}", e.doc, e.pos)

def main():
    """Main function to run test cases."""
    # Use command line argument if provided
    if len(sys.argv) > 1:
        url_arg = sys.argv[1]
        print(f"--- Testing with provided URL: {url_arg} ---")
        try:
            json_obj = fetch_and_parse_json(url_arg)
            print("Success! Fetched JSON object:")
            print(json.dumps(json_obj, indent=4))
        except (ValueError, requests.exceptions.RequestException, json.JSONDecodeError) as e:
            print(f"Error: {e}", file=sys.stderr)
        print("\n--- Running built-in test cases ---\n")

    test_urls = [
        # 1. Valid JSON API endpoint
        "https://jsonplaceholder.typicode.com/posts/1",
        # 2. URL leading to non-JSON content (HTML)
        "https://www.google.com",
        # 3. URL that results in a 404 Not Found error
        "https://jsonplaceholder.typicode.com/posts/99999999",
        # 4. URL with a non-HTTPS scheme (will be rejected)
        "http://jsonplaceholder.typicode.com/posts/1",
        # 5. URL with an invalid domain
        "https://domain.invalid"
    ]

    for i, url in enumerate(test_urls, 1):
        print(f"--- Test Case {i}: {url} ---")
        try:
            json_obj = fetch_and_parse_json(url)
            print("Success! Fetched JSON object:")
            print(json.dumps(json_obj, indent=4))
        except (ValueError, requests.exceptions.RequestException, json.JSONDecodeError) as e:
            print(f"Error: {e}", file=sys.stderr)
        print()

if __name__ == "__main__":
    main()