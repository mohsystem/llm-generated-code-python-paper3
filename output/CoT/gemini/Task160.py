import requests
import socket
import ipaddress
from urllib.parse import urlparse

# Security constants
CONNECT_TIMEOUT = 5.0 # 5 seconds
READ_TIMEOUT = 5.0 # 5 seconds
MAX_RESPONSE_SIZE = 4096 # Limit response to 4KB to prevent DoS

def make_http_request(url_string: str) -> str:
    """
    Makes a safe HTTP GET request to a URL.

    Args:
        url_string: The URL to request.

    Returns:
        The response content or an error message.
    """
    try:
        # 1. URL Parsing and Validation
        parsed_url = urlparse(url_string)

        # 2. Security Check: Protocol validation (Allowlist)
        if parsed_url.scheme not in ['http', 'https']:
            return "Error: Invalid protocol. Only HTTP and HTTPS are allowed."

        # 3. Security Check: SSRF Prevention
        hostname = parsed_url.hostname
        if not hostname:
            return "Error: Invalid URL, no hostname found."
            
        ip_addr = socket.gethostbyname(hostname)
        ip = ipaddress.ip_address(ip_addr)
        
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return "Error: SSRF attempt detected. Requests to local/private networks are not allowed."

        # 4. Make the request
        with requests.get(
            url_string, 
            timeout=(CONNECT_TIMEOUT, READ_TIMEOUT), 
            stream=True, 
            # Security: Disable redirects to prevent bypassing SSRF checks
            allow_redirects=False
        ) as response:
            status_code = response.status_code
            # Read a limited chunk of the response to prevent DoS
            content_chunk = response.raw.read(MAX_RESPONSE_SIZE, decode_content=True)
            
            result = f"Status Code: {status_code}\n"
            result += f"Response Body (first {MAX_RESPONSE_SIZE} bytes):\n"
            try:
                result += content_chunk.decode('utf-8', errors='ignore')
            except Exception:
                result += "[Could not decode response as UTF-8]"
            
            return result

    except requests.exceptions.RequestException as e:
        return f"Error: Request failed. {e}"
    except socket.gaierror:
        return "Error: Host could not be resolved."
    except Exception as e:
        return f"An unexpected error occurred: {e}"

if __name__ == "__main__":
    test_urls = [
        "https://api.ipify.org",  # Valid public URL
        "http://google.com",  # Valid public URL that redirects
        "http://127.0.0.1",  # SSRF test (loopback)
        "http://192.168.1.1",  # SSRF test (private network)
        "https://thissitedoesnotexist.invalidtld",  # Invalid host
        "file:///etc/passwd"  # Invalid protocol test
    ]

    for url in test_urls:
        print("=========================================")
        print(f"Requesting URL: {url}")
        print("-----------------------------------------")
        response = make_http_request(url)
        print(response)
        print("=========================================\n")