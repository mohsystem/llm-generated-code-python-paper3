import requests
import socket
import ipaddress
from urllib.parse import urlparse

CONNECT_TIMEOUT = 5.0
READ_TIMEOUT = 5.0
TIMEOUTS = (CONNECT_TIMEOUT, READ_TIMEOUT)
MAX_RESPONSE_BYTES = 1024  # Limit response to 1KB

def is_ip_unsafe(ip_str: str) -> bool:
    """
    Checks if an IP address string is unsafe to connect to from a server.
    This includes private, loopback, link-local, and other non-public addresses.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_unspecified
    except ValueError:
        return True  # Treat resolution failures or invalid IPs as unsafe

def make_http_request(url_string: str) -> str:
    """
    Securely makes an HTTP GET request to a given URL.
    """
    try:
        # 1. Parse and Validate URL structure and scheme
        parsed_uri = urlparse(url_string)
        if parsed_uri.scheme not in ('http', 'httpsor'):
            return "Error: Invalid or disallowed scheme. Only HTTP and HTTPS are allowed."

        hostname = parsed_uri.hostname
        if not hostname:
            return "Error: Could not determine host from URL."

        # 2. Resolve hostname and validate IP address against blocklist
        try:
            # getaddrinfo is preferred as it handles both IPv4 and IPv6
            addr_info = socket.getaddrinfo(hostname, parsed_uri.port, proto=socket.IPPROTO_TCP)
            
            # Check all resolved IPs
            for _, _, _, _, sockaddr in addr_info:
                ip_address = sockaddr[0]
                if is_ip_unsafe(ip_address):
                    return f"Error: SSRF attempt detected. Host resolves to a blocked IP address: {ip_address}"
        except socket.gaierror:
            return f"Error: Could not resolve hostname: {hostname}"

        # 3. Make the HTTP request with security measures
        with requests.get(
            url_string,
            timeout=TIMEOUTS,
            stream=True,  # To control response size
            allow_redirects=False, # To prevent redirect-based SSRF
            verify=True # Ensure SSL/TLS certificates are verified
        ) as response:
            
            response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)

            # 4. Read response with a size limit to prevent DoS
            content = response.raw.read(MAX_RESPONSE_BYTES, decode_content=True)
            return f"Success (first {MAX_RESPONSE_BYTES} bytes): {content.decode('utf-8', errors='ignore')}"

    except requests.exceptions.Timeout:
        return "Error: Request timed out."
    except requests.exceptions.SSLError as e:
        return f"Error: SSL verification failed: {e}"
    except requests.exceptions.RequestException as e:
        return f"An unexpected error occurred: {type(e).__name__} - {e}"
    except Exception as e:
        return f"An unexpected error occurred: {type(e).__name__} - {e}"

def main():
    test_urls = [
        "https://www.example.com",     # Valid public URL
        "http://127.0.0.1/status",    # SSRF attempt (loopback IP)
        "http://localhost/admin",       # SSRF attempt (loopback name)
        "https://192.168.1.1",        # SSRF attempt (private IP)
        "file:///etc/passwd",           # SSRF attempt (disallowed scheme)
        "http://[::1]/",               # SSRF attempt (IPv6 loopback)
        "ftp://ftp.example.com"        # SSRF attempt (disallowed scheme)
    ]

    for url in test_urls:
        print(f"Testing URL: {url}")
        result = make_http_request(url)
        print(f"Result: {result}")
        print("---------------------------------")

if __name__ == "__main__":
    main()