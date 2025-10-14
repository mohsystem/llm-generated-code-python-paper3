import urllib.request
import urllib.error

def make_http_request(url_string):
    """
    Makes an HTTP GET request to the specified URL.
    
    :param url_string: The URL to make the request to.
    :return: A string containing the HTTP status and the response body or an error message.
    """
    try:
        # The 'with' statement ensures the response object is properly closed.
        with urllib.request.urlopen(url_string, timeout=5) as response:
            # Read and decode the response.
            # It attempts to get the charset from headers, defaulting to 'utf-8'.
            charset = response.info().get_content_charset() or 'utf-8'
            data = response.read().decode(charset)
            return f"Status: {response.status}\nResponse:\n{data}"
    except urllib.error.HTTPError as e:
        # Handles HTTP errors (e.g., 404 Not Found, 500 Internal Server Error)
        return f"HTTP Error: {e.code} {e.reason}"
    except urllib.error.URLError as e:
        # Handles non-HTTP errors (e.g., DNS failure, connection refused)
        return f"URL Error: {e.reason}"
    except Exception as e:
        # Catches other potential errors, like timeouts
        return f"An unexpected error occurred: {e}"

def main():
    test_urls = [
        "https://jsonplaceholder.typicode.com/todos/1",
        "https://httpbin.org/get",
        "https://api.ipify.org?format=json",
        "https://www.google.com",
        "http://thissitedoesnotexist.invalidtld/"
    ]

    for url in test_urls:
        print(f"Testing URL: {url}")
        result = make_http_request(url)
        
        # Truncate long responses for better readability in the console
        if len(result) > 300:
            print(f"Result (first 300 chars):\n{result[:300]}...\n")
        else:
            print(f"Result:\n{result}\n")
        print("----------------------------------------")

if __name__ == "__main__":
    main()