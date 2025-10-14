import sys
import re
from urllib import request, error, parse

def get_page_title(url_string: str) -> str:
    """
    Makes an HTTPS call to a URL, retrieves the content, and extracts the page title.

    Args:
        url_string: The HTTPS URL to fetch.

    Returns:
        The extracted page title, or an error message if it fails.
    """
    # 1. Input Validation
    try:
        parsed_url = parse.urlparse(url_string)
        if not parsed_url.scheme == 'https':
            return "Error: URL must use HTTPS."
        if not parsed_url.netloc:
            return "Error: Invalid URL format (missing domain)."
    except ValueError:
        return "Error: Invalid URL format."

    try:
        # 2. Secure Request: urllib performs certificate validation by default.
        # Use a realistic User-Agent header to avoid being blocked.
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        req = request.Request(url_string, headers=headers)
        
        # Use 'with' for automatic resource management
        with request.urlopen(req, timeout=10) as response:
            # 3. Check for successful response
            if response.getcode() != 200:
                return f"Error: Received non-200 status code: {response.getcode()}"
            
            # Read and decode the response body safely
            # Limit the amount of data read to prevent potential DoS attacks
            charset = response.info().get_content_charset() or 'utf-8'
            html_content = response.read(1024 * 512).decode(charset, errors='ignore')

            # 4. Secure Parsing: Use a simple, non-greedy regex to find the title
            # re.IGNORECASE makes the tag search case-insensitive
            match = re.search(r'<title.*?>(.*?)</title>', html_content, re.IGNORECASE | re.DOTALL)
            if match:
                return match.group(1).strip()
            else:
                return "Error: Title tag not found."

    # 5. Handle exceptions gracefully
    except error.HTTPError as e:
        return f"Error: HTTP Error {e.code}: {e.reason}"
    except error.URLError as e:
        return f"Error: URL Error: {e.reason}"
    except Exception as e:
        return f"Error: An unexpected error occurred: {e}"

def main():
    # Test cases
    test_urls = [
        "https://www.google.com",
        "https://github.com",
        "https://www.microsoft.com/en-us/",
        "https://www.w3.org/",
        "https://example.com"
    ]
    
    print("--- Running 5 Test Cases ---")
    for url in test_urls:
        print(f"URL: {url}")
        title = get_page_title(url)
        print(f"Title: {title}")
        print("--------------------")

    # Handling command line arguments
    if len(sys.argv) > 1:
        print("\n--- Running with Command Line Argument ---")
        url_from_arg = sys.argv[1]
        print(f"URL: {url_from_arg}")
        title = get_page_title(url_from_arg)
        print(f"Title: {title}")
        print("--------------------")
    else:
        print("\nNote: You can also provide a URL as a command-line argument.")

if __name__ == '__main__':
    main()