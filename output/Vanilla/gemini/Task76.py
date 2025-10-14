import urllib.request
import re
import sys

def get_page_title(url):
    """
    Fetches the content of a URL and extracts the page title.
    """
    try:
        # Some sites block default Python User-Agent, so we use a common one.
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        req = urllib.request.Request(url, headers=headers)
        
        with urllib.request.urlopen(req, timeout=10) as response:
            if response.getcode() == 200:
                html_bytes = response.read()
                # Try decoding with utf-8, but fall back if it fails
                try:
                    html_string = html_bytes.decode('utf-8')
                except UnicodeDecodeError:
                    html_string = html_bytes.decode('latin-1', errors='ignore')

                # Use regex to find title. re.DOTALL allows . to match newlines.
                match = re.search(r'<title.*?>(.*?)</title>', html_string, re.IGNORECASE | re.DOTALL)
                if match:
                    return match.group(1).strip()
                else:
                    return "Title not found."
            else:
                return f"Error: Received status code {response.getcode()}"
    except Exception as e:
        return f"Error fetching URL: {e}"

def main():
    if len(sys.argv) > 1:
        url = sys.argv[1]
        print(f"Processing URL from command line: {url}")
        title = get_page_title(url)
        print(f"Title: {title}")
        print("\n--- Running built-in test cases ---")

    test_urls = [
        "https://www.google.com",
        "https://github.com",
        "https://www.oracle.com/java/",
        "https://www.python.org",
        "https://isocpp.org"
    ]
    
    for url in test_urls:
        print(f"Fetching title for: {url}")
        title = get_page_title(url)
        print(f"-> Title: {title}\n")

if __name__ == "__main__":
    main()