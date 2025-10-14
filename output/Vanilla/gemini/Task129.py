import urllib.request
import urllib.error

def retrieve_file_from_server(base_url, file_name):
    """
    Retrieves the content of a file from a server.
    :param base_url: The base URL of the server (e.g., "https://example.com/files").
    :param file_name: The name of the file to retrieve (e.g., "data.txt").
    :return: The content of the file as a string, or an error message if it fails.
    """
    if not file_name or not file_name.strip():
        return "Error: File name cannot be empty."

    # Ensure the base URL ends with a slash if it doesn't already
    if not base_url.endswith('/'):
        base_url += '/'
        
    full_url = base_url + file_name
    try:
        with urllib.request.urlopen(full_url, timeout=5) as response:
            if 200 <= response.status < 300:
                # The response data is in bytes, so we decode it to a string.
                return response.read().decode('utf-8')
            else:
                return f"Error: Failed to retrieve file. HTTP status code: {response.status}"
    except urllib.error.HTTPError as e:
        return f"Error: HTTP Error {e.code}: {e.reason}"
    except urllib.error.URLError as e:
        return f"Error: URL Error: {e.reason}"
    except Exception as e:
        return f"An unexpected error occurred: {e}"

def main():
    base_url = "https://jsonplaceholder.typicode.com"
    test_files = [
        "todos/1",
        "posts/10",
        "users/5",
        "nonexistent/path",  # This will cause a 404
        ""  # Empty file name
    ]

    for i, file in enumerate(test_files, 1):
        print(f"--- Test Case {i}: Retrieving '{file}' ---")
        result = retrieve_file_from_server(base_url, file)
        print(f"Result:\n{result}")
        print(f"--- End Test Case {i} ---\n")

if __name__ == "__main__":
    main()