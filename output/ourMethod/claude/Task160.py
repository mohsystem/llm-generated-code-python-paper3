
import re
import urllib.parse
import urllib.request
import ssl
import socket
from typing import Optional
def validate_url(url: str) -> bool:
    """
    Validate URL format and ensure it uses HTTPS protocol only.
    Security: Prevents SSRF attacks by enforcing HTTPS and validating format.
    """
    if not url or not isinstance(url, str):
        return False

    # Maximum URL length check to prevent memory exhaustion
    if len(url) > 2048:
        return False

    # Parse URL to validate structure
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return False

    # Only allow HTTPS protocol - Security: prevents unencrypted communication
    if parsed.scheme != 'https':
        return False

    # Validate hostname exists and is not empty
    if not parsed.netloc:
        return False

    # Block localhost, private IPs, and local network access - Security: prevents SSRF
    hostname = parsed.hostname
    if not hostname:
        return False

    # Block common local/private hostnames
    blocked_hosts = ['localhost', '127.0.0.1', '0.0.0.0', '::1', '[::1]']
    if hostname.lower() in blocked_hosts:
        return False

    # Try to resolve hostname and check if it's a private IP
    try:
        ip_addr = socket.gethostbyname(hostname)
        # Block private IP ranges - Security: prevents SSRF to internal networks
        if (
                ip_addr.startswith('10.')
                or ip_addr.startswith('192.168.')
                or ip_addr.startswith('172.')
                or ip_addr.startswith('127.')
        ):
            return False
    except (socket.gaierror, socket.herror):
        return False

    return True


def make_http_request(url: str) -> Optional[str]:
    """
    Make HTTPS GET request to the validated URL.
    Security: Uses SSL/TLS with certificate verification, hostname validation.
    Returns response content or None on error.
    """
    # Validate input URL first - Security: input validation
    if not validate_url(url):
        return None

    try:
        # Create SSL context with secure defaults
        # Security: Enforces certificate validation and hostname verification
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = True  # Security: hostname verification enabled
        ssl_context.verify_mode = ssl.CERT_REQUIRED  # Security: certificate validation required

        # Set timeout to prevent indefinite hanging - Security: prevents DoS
        timeout = 10

        # Create request with User-Agent header
        request = urllib.request.Request(
            url,
            headers={'User-Agent': 'SecureHTTPClient/1.0'}
        )

        # Make HTTPS request with SSL context
        # Security: Uses validated SSL/TLS connection with cert verification
        with urllib.request.urlopen(
                request,
                timeout=timeout,
                context=ssl_context
        ) as response:
            # Limit response size to prevent memory exhaustion - Security: DoS prevention
            max_size = 1024 * 1024  # 1MB limit
            content = response.read(max_size)

            # Decode response safely
            # Security: Uses UTF-8 with error handling to prevent injection
            return content.decode('utf-8', errors='ignore')

    except urllib.error.URLError:
        # Security: Don't expose detailed error messages to user
        return None
    except ssl.SSLError:
        # Security: SSL/TLS errors indicate cert validation failure
        return None
    except socket.timeout:
        # Security: Timeout prevents hanging connections
        return None
    except Exception:
        # Security: Catch-all to prevent unexpected crashes
        return None

def main() -> None:
    """\n    Main function with test cases demonstrating secure URL handling.\n    """
    print("Secure HTTPS Request Program")
    print("=" * 50)
    
    # Test cases with various scenarios
    test_urls = [
        # Valid HTTPS URL (example)
        "https://www.example.com",
        # Invalid: HTTP instead of HTTPS
        "http://www.example.com",
        # Invalid: localhost (SSRF prevention)
        "https://localhost/admin",
        # Invalid: private IP (SSRF prevention)
        "https://192.168.1.1/secret",
        # Invalid: malformed URL
        "not-a-valid-url"
    ]
    
    for i, test_url in enumerate(test_urls, 1):
        print(f"\\nTest Case {i}:")
        print(f"URL: {test_url}")
        
        # Attempt to make request
        result = make_http_request(test_url)
        
        if result is not None:
            # Limit output display for readability
            preview = result[:200] if len(result) > 200 else result
            print(f"Success: Retrieved {len(result)} bytes")
            print(f"Preview: {preview}...")
        else:
            print("Failed: URL validation failed or request error")
    
    # Interactive mode - accept user input
    print("\\n" + "=" * 50)
    print("\\nEnter a URL to fetch (or 'quit' to exit):")
    
    # Note: In production, read from stdin with proper validation
    # For demonstration, showing the validation flow
    user_url = "https://www.example.com"  # Placeholder for user input
    print(f"Processing: {user_url}")
    
    result = make_http_request(user_url)
    if result is not None:
        print(f"\\nSuccess! Retrieved {len(result)} bytes from {user_url}")
    else:
        print(f"\\nError: Unable to fetch URL. Ensure it's a valid HTTPS URL to a public domain.")

if __name__ == "__main__":
    main()
