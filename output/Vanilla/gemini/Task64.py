import json
import urllib.request
import urllib.error

def read_json_from_url(url_string):
    """
    Fetches content from a URL, parses it as JSON, and returns the object.
    
    :param url_string: The URL to fetch JSON from.
    :return: A Python dictionary or list representing the JSON data, or None on error.
    """
    try:
        with urllib.request.urlopen(url_string, timeout=5) as response:
            if 200 <= response.status < 300:
                data = response.read()
                encoding = response.info().get_content_charset('utf-8')
                return json.loads(data.decode(encoding))
            else:
                print(f"Error: Received status code {response.status}")
                return None
    except urllib.error.HTTPError as e:
        print(f"HTTP Error: {e.code} {e.reason}")
        return None
    except urllib.error.URLError as e:
        print(f"URL Error: {e.reason}")
        return None
    except json.JSONDecodeError as e:
        print(f"JSON Decode Error: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None

def main():
    """Main function with test cases."""
    test_urls = [
        "https://jsonplaceholder.typicode.com/todos/1",
        "https://jsonplaceholder.typicode.com/posts/1",
        "https://jsonplaceholder.typicode.com/users/1",
        "https://jsonplaceholder.typicode.com/posts",  # This is a JSON array
        "https://jsonplaceholder.typicode.com/nonexistent"  # This will cause an HTTP 404 error
    ]

    for url in test_urls:
        print(f"Fetching from: {url}")
        json_object = read_json_from_url(url)
        if json_object is not None:
            # Pretty print the JSON
            print(json.dumps(json_object, indent=4))
        print("----------------------------------------")

if __name__ == "__main__":
    main()