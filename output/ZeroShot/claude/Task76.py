
import sys
import re
import urllib.request
import urllib.error
import ssl

def get_page_title(url_string):
    if not url_string or not url_string.strip():
        return "Invalid URL"
    
    # Validate HTTPS URL
    if not url_string.lower().startswith("https://"):
        return "Only HTTPS URLs are allowed"
    
    try:
        # Create SSL context for secure connection
        context = ssl.create_default_context()
        
        # Create request with headers
        req = urllib.request.Request(
            url_string,
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        
        # Open URL with timeout
        with urllib.request.urlopen(req, timeout=5, context=context) as response:
            if response.status != 200:
                return f"Failed to retrieve page. Response code: {response.status}"
            
            # Read content with size limit
            content = response.read(1000000).decode('utf-8', errors='ignore')
            
            # Extract title using regex
            pattern = re.compile(r'<title>(.*?)</title>', re.IGNORECASE | re.DOTALL)
            match = pattern.search(content)
            
            if match:
                return match.group(1).strip()
            else:
                return "No title found"
                
    except urllib.error.URLError as e:
        return f"Error: {str(e)}"
    except Exception as e:
        return f"Error: {str(e)}"

def main():
    if len(sys.argv) > 1:
        result = get_page_title(sys.argv[1])
        print(f"Title: {result}")
    else:
        # Test cases
        print("Test Case 1:")
        print(get_page_title("https://www.example.com"))
        
        print("\\nTest Case 2:")
        print(get_page_title("https://www.google.com"))
        
        print("\\nTest Case 3:")
        print(get_page_title("http://www.example.com"))
        
        print("\\nTest Case 4:")
        print(get_page_title(""))
        
        print("\\nTest Case 5:")
        print(get_page_title(None))

if __name__ == "__main__":
    main()
