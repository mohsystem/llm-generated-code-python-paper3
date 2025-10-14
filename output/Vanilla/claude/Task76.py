
import sys
import re
try:
    from urllib.request import urlopen, Request
except ImportError:
    from urllib2 import urlopen, Request

def get_page_title(url_string):
    try:
        request = Request(url_string, headers={'User-Agent': 'Mozilla/5.0'})
        response = urlopen(request, timeout=5)
        content = response.read().decode('utf-8', errors='ignore')
        response.close()
        
        match = re.search(r'<title>(.*?)</title>', content, re.IGNORECASE)
        
        if match:
            return match.group(1).strip()
        
        return "No title found"
    except Exception as e:
        return f"Error: {str(e)}"

if __name__ == "__main__":
    test_urls = [
        "https://www.example.com",
        "https://www.google.com",
        "https://www.github.com",
        "https://www.stackoverflow.com",
        "https://www.wikipedia.org"
    ]
    
    if len(sys.argv) > 1:
        print(f"URL: {sys.argv[1]}")
        print(f"Title: {get_page_title(sys.argv[1])}")
    else:
        print("Running test cases:")
        for url in test_urls:
            print(f"\\nURL: {url}")
            print(f"Title: {get_page_title(url)}")
