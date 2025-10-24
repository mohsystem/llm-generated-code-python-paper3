import sys
import json
import requests
from urllib.parse import urlparse
from typing import Any, Dict, List, Union

# Define a type for JSON objects for better type hinting.
JsonType = Union[Dict[str, Any], List[Any], str, int, float, bool, None]

def fetch_json_from_url(url: str) -> JsonType:
    """
    Fetches a file from a URL, parses its JSON content, and returns the object.

    Args:
        url: The URL to fetch the JSON file from. It must be a valid URL
             using the HTTPS scheme.

    Returns:
        The parsed JSON object from the URL content.

    Raises:
        ValueError: If the URL is invalid, not using HTTPS, or if the
                    response content is not valid JSON.
        requests.exceptions.RequestException: For network-related errors
                                              (e.g., DNS failure, connection refused).
    """
    # Rule #5: Validate input. Ensure the URL is well-formed and uses HTTPS.
    parsed_url = urlparse(url)
    if not all([parsed_url.scheme, parsed_url.netloc]):
        raise ValueError("Invalid URL format provided. A scheme and network location are required.")
    if parsed_url.scheme != 'https':
        raise ValueError("URL must use the HTTPS scheme for security.")

    # A reasonable timeout to prevent the application from hanging indefinitely.
    timeout_seconds = 10

    try:
        # Rule #3 & #4: requests handles certificate and hostname validation by default.
        # Rule #8: Use try-with-resources (context manager) and catch exceptions.
        with requests.get(url, timeout=timeout_seconds) as response:
            # Raise an HTTPError for bad responses (4xx or 5xx)
            response.raise_for_status()

            # Rule #1: Use safe parsing. The requests library's .json() method
            # uses the standard, safe json library and is the preferred way.
            # This will raise a JSONDecodeError if parsing fails.
            return response.json()

    except requests.exceptions.RequestException as e:
        # This is a broad exception for network-related issues.
        # Re-raise it to allow the caller to handle network problems.
        raise e
    except (json.JSONDecodeError, requests.exceptions.JSONDecodeError):
        # If .json() fails, it raises an exception. Catch it and raise a
        # more semantic ValueError indicating a content problem.
        raise ValueError("The response from the URL was not valid JSON.")


def main():
    """
    Main function with 5 test cases to demonstrate fetch_json_from_url.
    
    This function demonstrates how to use `fetch_json_from_url`. In a real
    command-line application, you would typically read the URL from `sys.argv`.
    """
    test_cases = [
        # 1. Success case: A valid JSON object from a reputable API.
        "https://jsonplaceholder.typicode.com/todos/1",
        # 2. HTTP Error case: A URL that should result in a 404 Not Found.
        "https://jsonplaceholder.typicode.com/nonexistent/path",
        # 3. Content Error case: A valid URL that returns HTML, not JSON.
        "https://www.example.com",
        # 4. URL Scheme Error case: Using HTTP instead of the required HTTPS.
        "http://jsonplaceholder.typicode.com/todos/1",
        # 5. Invalid URL Format case: A malformed string that is not a URL.
        "this is not a url"
    ]

    for i, url in enumerate(test_cases, 1):
        print(f"--- Test Case {i}: Fetching URL: {url} ---")
        try:
            json_data = fetch_json_from_url(url)
            print("Success! Fetched and parsed JSON.")
            # Pretty-print the JSON data for readability
            print(json.dumps(json_data, indent=2))
        except ValueError as e:
            print(f"Failed as expected (ValueError): {e}", file=sys.stderr)
        except requests.exceptions.HTTPError as e:
            print(f"Failed as expected (HTTPError): {e}", file=sys.stderr)
        except requests.exceptions.RequestException as e:
            print(f"Failed as expected (RequestException): {e}", file=sys.stderr)
        except Exception as e:
            print(f"An unexpected error occurred: {e}", file=sys.stderr)
        finally:
            print("-" * 40 + "\n")


if __name__ == "__main__":
    # To run with a command-line argument, you could do the following:
    # if len(sys.argv) == 2:
    #     try:
    #         data = fetch_json_from_url(sys.argv[1])
    #         print(json.dumps(data, indent=2))
    #     except Exception as e:
    #         print(f"Error processing URL '{sys.argv[1]}': {e}", file=sys.stderr)
    #         sys.exit(1)
    # else:
    #     print(f"Usage: python {sys.argv[0]} <https_url>", file=sys.stderr)
    #     main() # Run test cases if no argument is provided
    main()