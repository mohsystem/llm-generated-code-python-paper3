
import urllib.request
import urllib.error

def make_http_request(url_string):
    try:
        request = urllib.request.Request(url_string)
        request.add_header('User-Agent', 'Mozilla/5.0')
        
        with urllib.request.urlopen(request, timeout=5) as response:
            response_code = response.getcode()
            content = response.read().decode('utf-8')
            return f"Response Code: {response_code}\\n{content}"
            
    except urllib.error.HTTPError as e:
        return f"HTTP Error: {e.code} - {e.reason}"
    except urllib.error.URLError as e:
        return f"URL Error: {e.reason}"
    except Exception as e:
        return f"Error: {str(e)}"

if __name__ == "__main__":
    # Test cases
    test_urls = [
        "https://jsonplaceholder.typicode.com/posts/1",
        "https://api.github.com/users/github",
        "https://httpbin.org/get",
        "https://www.google.com",
        "https://example.com"
    ]
    
    for i, url in enumerate(test_urls, 1):
        print(f"Test Case {i}: {url}")
        result = make_http_request(url)
        print(result[:200] + "...\\n")
