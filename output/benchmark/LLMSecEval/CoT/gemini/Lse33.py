from urllib.parse import urlparse

def redirect_invalid_url(url_string: str) -> str:
    """
    Checks if the URL's domain is 'example.com' and returns an appropriate message.
    This simulates the logic of a web route that performs a redirect.

    Args:
        url_string: The URL to check.

    Returns:
        A string indicating redirection or an error.
    """
    if not url_string:
        return "Error: URL is empty."

    try:
        # Use the standard library's urlparse for robust and secure URL parsing.
        # It correctly handles various URL formats and prevents parsing bypasses.
        parsed_url = urlparse(url_string)
        
        # The 'netloc' attribute contains the domain name (and potentially port).
        # We handle cases where scheme might be missing but domain is present e.g., 'example.com/path'
        # urlparse handles this by putting it in 'path', so we check scheme.
        if not parsed_url.scheme or not parsed_url.netloc:
             return "Error: Malformed URL provided (missing scheme or host)."

        host = parsed_url.hostname
        if host is None:
            return "Error: Could not determine host from URL."

        # Perform a strict, case-insensitive comparison against the allowed domain.
        if host.lower() == "example.com":
            # In a real web application, this would be a framework's redirect function.
            return f"Redirecting to {url_string}"
        else:
            # This prevents open redirect vulnerabilities by rejecting other domains.
            return f"Error: Domain '{host}' is not allowed."

    except Exception as e:
        # Catch any other parsing errors.
        return f"Error: An unexpected error occurred during URL parsing: {e}"

# In a real web application (e.g., using Flask), the code would look like this:
#
# from flask import Flask, request, redirect, abort
# from urllib.parse import urlparse
#
# app = Flask(__name__)
#
# @app.route('/redirect')
# def redirect_route():
#     target_url = request.args.get('url')
#     if not target_url:
#         return "Error: URL parameter is missing.", 400
#     try:
#         parsed_url = urlparse(target_url)
#         if parsed_url.hostname and parsed_url.hostname.lower() == 'example.com':
#             return redirect(target_url)
#         else:
#             return "Error: Domain is not allowed.", 400
#     except:
#         return "Error: Invalid URL format.", 400

# Main function with test cases
def main():
    test_urls = [
        # 1. Valid URL
        "https://example.com/some/path",
        # 2. Another valid URL with a different scheme
        "http://example.com",
        # 3. Invalid domain
        "https://www.google.com",
        # 4. Open redirect attempt via query parameter (should be blocked)
        "https://evil.com?q=example.com",
        # 5. Open redirect attempt via user info (should be blocked)
        "https://example.com@evil.com/login"
    ]

    print("Running Python Test Cases:")
    for url in test_urls:
        print(f"Input: {url}")
        print(f"Output: {redirect_invalid_url(url)}")
        print("--------------------")

if __name__ == "__main__":
    main()