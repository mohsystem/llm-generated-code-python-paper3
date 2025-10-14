
import json
import urllib.request
import sys

def read_json_from_url(url):
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            content = response.read().decode('utf-8')
            return content
    except Exception as e:
        print(f"Error reading URL: {e}", file=sys.stderr)
        return None

def parse_json(url):
    try:
        json_content = read_json_from_url(url)
        if json_content:
            return json.loads(json_content)
        return None
    except Exception as e:
        print(f"Error parsing JSON: {e}", file=sys.stderr)
        return None

if __name__ == "__main__":
    # Test cases with publicly available JSON APIs
    test_urls = [
        "https://jsonplaceholder.typicode.com/posts/1",
        "https://jsonplaceholder.typicode.com/users/1",
        "https://jsonplaceholder.typicode.com/comments/1",
        "https://jsonplaceholder.typicode.com/todos/1",
        "https://jsonplaceholder.typicode.com/albums/1"
    ]
    
    for i, url in enumerate(test_urls, 1):
        print(f"Test Case {i}:")
        print(f"URL: {url}")
        result = parse_json(url)
        if result:
            print(f"JSON Object: {json.dumps(result, indent=2)}")
        print()
