import json
import urllib.request
import urllib.error
import socket

def fetch_json_from_url(url_string):
    """
    Fetches content from a URL, parses it as JSON, and returns the object.

    Args:
        url_string: The URL to fetch the JSON from.

    Returns:
        A Python dictionary or list representing the JSON, or None on failure.
    """
    if not url_string:
        print("Error: URL string is empty.")
        return None
        
    try:
        # Set a timeout to prevent the program from hanging.
        # A request object can be used for more complex headers if needed.
        with urllib.request.urlopen(url_string, timeout=5) as response:
            if response.status == 200:
                # Read and decode the response body.
                data = response.read().decode('utf-8')
                # Parse the JSON string.
                return json.loads(data)
            else:
                print(f"Error: HTTP request failed with status code: {response.status}")
                return None
    except ValueError:
        print(f"Error: Invalid URL provided: {url_string}")
        return None
    except urllib.error.HTTPError as e:
        print(f"Error: HTTP Error: {e.code} {e.reason}")
        return None
    except urllib.error.URLError as e:
        print(f"Error: URL Error: {e.reason}")
        return None
    except socket.timeout:
        print("Error: Request timed out.")
        return None
    except json.JSONDecodeError:
        print("Error: Failed to decode JSON from response.")
        return None

def main():
    """Main function to run test cases."""
    test_urls = [
        # 1. Valid JSON URL
        "https://jsonplaceholder.typicode.com/posts/1",
        # 2. URL pointing to non-JSON content (HTML)
        "http://example.com",
        # 3. URL that results in a 404 Not Found error
        "https://jsonplaceholder.typicode.com/posts/99999",
        # 4. Malformed URL
        "htp:/invalid-url",
        # 5. Non-existent domain
        "http://domain.that.does.not.exist"
    ]
    
    for i, url in enumerate(test_urls, 1):
        print(f"--- Test Case {i}: {url} ---")
        result = fetch_json_from_url(url)
        if result:
            print(f"Success! Fetched JSON object. Keys: {list(result.keys()) if isinstance(result, dict) else 'N/A'}")
            # To print the full JSON, uncomment the following line:
            # print(json.dumps(result, indent=4))
        else:
            print("Failure! As expected or due to an error.")
        print()

if __name__ == "__main__":
    import sys
    # Command-line argument handling
    if len(sys.argv) > 1:
        url_arg = sys.argv[1]
        print(f"Fetching JSON from command-line argument: {url_arg}")
        json_data = fetch_json_from_url(url_arg)
        if json_data:
            print("Successfully fetched and parsed JSON:\n", json.dumps(json_data, indent=4))
        else:
            print("Failed to fetch or parse JSON.")
        print("\n--- Running built-in test cases ---\n")
    
    main()