
import json
import urllib.request
import urllib.error
import sys
from urllib.parse import urlparse

def fetch_and_parse_json(url_string):
    if not url_string or not url_string.strip():
        raise ValueError("URL cannot be None or empty")
    
    try:
        # Validate URL format
        parsed_url = urlparse(url_string)
        
        # Only allow HTTP and HTTPS protocols
        if parsed_url.scheme.lower() not in ['http', 'https']:
            raise ValueError("Only HTTP and HTTPS protocols are allowed")
        
        # Create request with timeout
        headers = {'User-Agent': 'Mozilla/5.0'}
        request = urllib.request.Request(url_string, headers=headers)
        
        # Fetch the content with timeout
        with urllib.request.urlopen(request, timeout=5) as response:
            if response.status != 200:
                raise RuntimeError(f"HTTP Error: {response.status}")
            
            # Read and decode the response
            content = response.read().decode('utf-8')
            
            # Parse JSON
            json_object = json.loads(content)
            return json_object
            
    except urllib.error.URLError as e:
        raise RuntimeError(f"Error fetching URL: {str(e)}")
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Error parsing JSON: {str(e)}")
    except Exception as e:
        raise RuntimeError(f"Error: {str(e)}")

def main():
    # Test cases
    print("Test Case 1: Valid JSON URL")
    try:
        result1 = fetch_and_parse_json("https://jsonplaceholder.typicode.com/todos/1")
        print(f"Result: {result1}")
    except Exception as e:
        print(f"Error: {str(e)}")
    
    print("\\nTest Case 2: Another valid JSON URL")
    try:
        result2 = fetch_and_parse_json("https://jsonplaceholder.typicode.com/users/1")
        print(f"Result: {result2}")
    except Exception as e:
        print(f"Error: {str(e)}")
    
    print("\\nTest Case 3: Invalid URL format")
    try:
        result3 = fetch_and_parse_json("not-a-valid-url")
        print(f"Result: {result3}")
    except Exception as e:
        print(f"Error: {str(e)}")
    
    print("\\nTest Case 4: Empty URL")
    try:
        result4 = fetch_and_parse_json("")
        print(f"Result: {result4}")
    except Exception as e:
        print(f"Error: {str(e)}")
    
    print("\\nTest Case 5: None URL")
    try:
        result5 = fetch_and_parse_json(None)
        print(f"Result: {result5}")
    except Exception as e:
        print(f"Error: {str(e)}")
    
    # Command line argument support
    if len(sys.argv) > 1:
        print(f"\\nCommand line URL: {sys.argv[1]}")
        try:
            result = fetch_and_parse_json(sys.argv[1])
            print(f"Result: {result}")
        except Exception as e:
            print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()
