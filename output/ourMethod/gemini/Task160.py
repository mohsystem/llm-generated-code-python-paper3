import socket
import ipaddress
import re
from urllib.parse import urlparse
import requests

# A regex to validate that the URL starts with http:// or https://
URL_SCHEME_PATTERN = re.compile(r'^https?://', re.IGNORECASE)

REQUEST_TIMEOUT = 5  # 5 seconds

def is_private_ip(hostname: str) -> bool:
    """
    Checks if a hostname resolves to a private, loopback, or link-local IP address.
    """
    try:
        # getaddrinfo can return multiple addresses, check all of them
        for res in socket.getaddrinfo(hostname, None):
            _, _, _, _, sockaddr = res
            ip_str = sockaddr[0]
            ip = ipaddress.ip_address(ip_str)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                print(f"Error: Host {hostname} resolves to a private IP address: {ip_str}")
                return True
    except socket.gaierror:
        print(f"Error: Could not resolve host: {hostname}")
        return True # Fail closed
    return False

def make_http_request(url: str) -> str:
    """
    Makes a safe HTTP GET request to a URL.
    Validates the URL, protocol, and host to prevent SSRF.
    """
    if not isinstance(url, str) or not url.strip():
        return "Error: URL must be a non-empty string."

    if not URL_SCHEME_PATTERN.match(url):
        return "Error: Invalid URL format or protocol. Only HTTP/HTTPS is allowed."

    try:
        parsed_url = urlparse(url)
        if not all([parsed_url.scheme, parsed_url.hostname]):
             return "Error: Malformed URL. Missing scheme or hostname."
    except ValueError:
        return "Error: Could not parse URL."

    if parsed_url.scheme not in ['http', 'https']:
        return "Error: Invalid protocol. Only HTTP and HTTPS are allowed."

    if is_private_ip(parsed_url.hostname):
        return "Error: SSRF attempt detected. Requests to private networks are not allowed."

    try:
        # The 'requests' library handles certificate validation by default
        with requests.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True) as response:
            response.raise_for_status() # Raises an HTTPError for bad responses (4xx or 5xx)
            # Return the first 1KB of content to prevent DoS from large responses
            return response.text[:1024]

    except requests.exceptions.RequestException as e:
        return f"Error: HTTP request failed: {e}"
    except Exception as e:
        return f"An unexpected error occurred: {e}"

def main():
    """Main function with test cases."""
    test_urls = [
        "https://api.github.com",  # Valid HTTPS
        "http://example.com",      # Valid HTTP
        "ftp://example.com",       # Invalid protocol
        "https://127.0.0.1",       # SSRF attempt (loopback)
        "https://localhost",       # SSRF attempt (loopback)
        "http://192.168.1.1",    # SSRF attempt (private)
        "not-a-url"                # Invalid format
    ]

    for i, url in enumerate(test_urls):
        print(f"---- Test Case {i + 1}: {url} ----")
        response = make_http_request(url)
        if len(response) > 300:
            print(response[:300] + "...")
        else:
            print(response)
        print("-------------------------------------------\n")

if __name__ == "__main__":
    main()