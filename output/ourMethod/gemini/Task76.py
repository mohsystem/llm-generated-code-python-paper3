import sys
import re
import requests
from urllib.parse import urlparse

class TitleExtractionError(Exception):
    """Custom exception for errors during title extraction."""
    pass

def get_page_title(url: str) -> str:
    """
    Makes an HTTPS call to a URL, retrieves the content, and extracts the page title.

    Args:
        url: The HTTPS URL of the webpage.

    Returns:
        The extracted page title as a string.

    Raises:
        TitleExtractionError: If the URL is invalid, the request fails,
                              or the title cannot be found.
    """
    # Rule #3: Ensure all input is validated.
    try:
        parsed_url = urlparse(url)
        if not all([parsed_url.scheme, parsed_url.netloc]):
            raise TitleExtractionError("Invalid URL format provided.")
        if parsed_url.scheme != "https":
            raise TitleExtractionError("URL must use the 'https' scheme.")
    except ValueError:
        raise TitleExtractionError("Invalid URL format provided.")

    try:
        # Rules #1, #2, #8: Use a trusted library (requests) that handles
        # SSL/TLS certificate validation, hostname verification, and modern
        # protocols by default. Set a user-agent as a good practice.
        # A timeout prevents the program from hanging indefinitely.
        headers = {
            'User-Agent': 'TitleExtractor/1.0 (Python)'
        }
        response = requests.get(url, timeout=10, headers=headers)
        
        # Raise an exception for bad status codes (4xx or 5xx).
        response.raise_for_status()

        # Rule #5: The requests library handles buffer management safely.
        html_content = response.text
        
        # Rule #4, #6: Use a simple, safe regular expression to parse the title.
        # This avoids complex parsers that might be vulnerable to attacks like XXE.
        # The regex is designed to be non-greedy and case-insensitive to handle
        # various HTML formats, and re.DOTALL allows the title to span newlines.
        match = re.search(r'<title[^>]*>(.*?)</title>', html_content, re.IGNORECASE | re.DOTALL)
        
        if match:
            # The title is in the first captured group.
            # Strip whitespace from the beginning and end.
            return match.group(1).strip()
        else:
            raise TitleExtractionError("Page title not found in the HTML content.")

    except requests.exceptions.RequestException as e:
        # Rule #12: Catch and handle network-related exceptions appropriately.
        raise TitleExtractionError(f"HTTP request failed: {e}") from e
    except Exception as e:
        # Catch any other unexpected errors during processing.
        if isinstance(e, TitleExtractionError):
            raise
        raise TitleExtractionError(f"An unexpected error occurred: {e}") from e

def run_tests():
    """Runs a set of 5 test cases."""
    print("--- Running 5 Test Cases ---")
    
    # A list of 5 valid URLs to test the function.
    test_urls = [
        "https://www.python.org",
        "https://www.google.com",
        "https://github.com",
        "https://www.djangoproject.com/",
        "https://www.kernel.org/"
    ]

    for i, url in enumerate(test_urls, 1):
        print(f"\n--- Test Case {i}: {url} ---")
        try:
            title = get_page_title(url)
            print(f"Success! Title: {title}")
        except TitleExtractionError as e:
            print(f"Failed! Error: {e}", file=sys.stderr)

def main():
    """
    Main function to handle command-line arguments and run test cases.
    """
    if len(sys.argv) == 2:
        # If a URL is provided as a command-line argument, process it.
        input_url = sys.argv[1]
        try:
            title = get_page_title(input_url)
            print(f"Title: {title}")
        except TitleExtractionError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        # If no URL is provided, show usage and run the built-in test cases.
        print(f"Usage: python {sys.argv[0]} <https_url>")
        run_tests()

if __name__ == "__main__":
    main()