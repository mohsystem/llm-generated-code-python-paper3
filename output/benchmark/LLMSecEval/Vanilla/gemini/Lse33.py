from urllib.parse import urlparse

def redirect_invalid_url(url_string):
    """
    Checks if the URL's domain is "example.com".

    Args:
        url_string: The URL to check.

    Returns:
        A redirection message if the domain is valid, otherwise an error message.
    """
    try:
        parsed_url = urlparse(url_string)
        # Check if the URL has a scheme (like http, https) and a netloc (domain)
        if not all([parsed_url.scheme, parsed_url.netloc]):
            return "Error: Malformed URL provided."

        domain = parsed_url.netloc
        if domain == "example.com":
            return f"Redirecting to {url_string}"
        else:
            return f"Error: Invalid domain. Only example.com is allowed. Domain was: {domain}"
    except Exception as e:
        return f"An unexpected error occurred: {e}"

def main():
    """Runs test cases for the redirect_invalid_url function."""
    test_urls = [
        "http://example.com/path/to/page",
        "https://www.google.com",
        "http://test.example.com",
        "ftp://example.com/resource",
        "example.com/no/protocol" # Malformed URL
    ]

    print("--- Running Python Test Cases ---")
    for url in test_urls:
        print(f"Input : {url}")
        print(f"Output: {redirect_invalid_url(url)}")
        print("---------------------------------")

if __name__ == "__main__":
    main()