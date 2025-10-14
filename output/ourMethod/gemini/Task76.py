import sys
import re
import urllib.request
import urllib.error
from typing import List

def extract_page_title(url: str) -> str:
    """
    Fetches content from a URL and extracts the page title.

    Args:
        url: The HTTPS URL to fetch.

    Returns:
        The page title, or an empty string if not found or an error occurs.
    """
    if not isinstance(url, str) or not url.lower().startswith("https://"):
        return ""

    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        req = urllib.request.Request(url, headers=headers)

        with urllib.request.urlopen(req, timeout=10) as response:
            if response.getcode() == 200:
                charset = response.info().get_content_charset() or 'utf-8'
                # Read only first 8KB to find the title
                html_bytes = response.read(8192)
                html_content = html_bytes.decode(charset, errors='ignore')
                
                # Use regex to find the title, case-insensitively, and handling newlines.
                match = re.search(r'<title.*?>(.*?)</title>', html_content, re.IGNORECASE | re.DOTALL)
                if match:
                    return match.group(1).strip()
    except (urllib.error.URLError, urllib.error.HTTPError, ValueError, TimeoutError):
        return ""
    
    return ""

def main(args: List[str]) -> None:
    if len(args) > 1:
        url = args[1]
        print(f"Extracting title from URL provided via command line: {url}")
        title = extract_page_title(url)
        if title:
            print(f"Page Title: {title}")
        else:
            print("Could not extract page title.")
        print("---")

    print("Running test cases...")
    test_urls = [
        "https://www.google.com",
        "https://example.com",
        "https://httpbin.org/html",
        "invalid-url",
        "https://thishostshouldnotexist12345.com"
    ]

    for i, url in enumerate(test_urls, 1):
        print(f"Test Case {i}: {url}")
        title = extract_page_title(url)
        if title:
            print(f"  -> Title: {title}")
        else:
            print("  -> Could not extract title (as expected for invalid cases).")


if __name__ == '__main__':
    main(sys.argv)