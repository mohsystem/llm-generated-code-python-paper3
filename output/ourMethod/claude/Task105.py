
import ssl
import socket
import sys
from typing import Optional, Tuple
from urllib.parse import urlparse


def create_secure_context() -> ssl.SSLContext:
    """\n    Create a secure SSL/TLS context with strict security settings.\n    \n    Returns:\n        ssl.SSLContext: Configured SSL context with TLS 1.2+ enforced\n    \n    Security: Enforces TLS 1.2+ to prevent downgrade attacks (CWE-327).\n    Certificate validation is enabled by default to prevent MITM (CWE-295, CWE-297).\n    """
    # Create default context with certificate validation enabled
    ctx = ssl.create_default_context()
    
    # Enforce hostname verification to prevent MITM attacks (CWE-297)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    
    # Force TLS 1.2 or higher to prevent protocol downgrade attacks (CWE-327)
    if hasattr(ssl, "TLSVersion"):  # Python 3.10+
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    else:  # Python 3.7-3.9
        # Disable insecure protocols
        ctx.options |= getattr(ssl, "OP_NO_SSLv2", 0)
        ctx.options |= getattr(ssl, "OP_NO_SSLv3", 0)
        ctx.options |= getattr(ssl, "OP_NO_TLSv1", 0)
        ctx.options |= getattr(ssl, "OP_NO_TLSv1_1", 0)
    
    return ctx


def parse_server_url(url: str) -> Tuple[str, int, str]:
    """\n    Parse and validate server URL.\n    \n    Args:\n        url: URL string to parse (e.g., "https://example.com:443")\n    \n    Returns:\n        Tuple of (hostname, port, scheme)\n    \n    Raises:\n        ValueError: If URL is invalid or not HTTPS\n    \n    Security: Validates URL format and enforces HTTPS to prevent insecure connections.\n    """
    if not url or not isinstance(url, str):
        raise ValueError("URL must be a non-empty string")
    
    # Limit URL length to prevent resource exhaustion
    if len(url) > 2048:
        raise ValueError("URL exceeds maximum length of 2048 characters")
    
    parsed = urlparse(url)
    
    # Only allow HTTPS to ensure encrypted connections
    if parsed.scheme != "https":
        raise ValueError("Only HTTPS URLs are supported")
    
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Invalid hostname in URL")
    
    # Validate hostname length (max 255 per RFC 1035)
    if len(hostname) > 255:
        raise ValueError("Hostname exceeds maximum length")
    
    # Get port or default to 443 for HTTPS
    port = parsed.port if parsed.port else 443
    
    # Validate port range
    if not isinstance(port, int) or port < 1 or port > 65535:
        raise ValueError("Port must be between 1 and 65535")
    
    return hostname, port, parsed.scheme


def establish_secure_connection(
    hostname: str, 
    port: int, 
    timeout: float = 10.0
) -> Tuple[ssl.SSLSocket, dict]:
    """\n    Establish a secure SSL/TLS connection to a remote server.\n    \n    Args:\n        hostname: Server hostname to connect to\n        port: Server port number\n        timeout: Connection timeout in seconds (default: 10.0)\n    \n    Returns:\n        Tuple of (ssl_socket, certificate_info)\n    \n    Raises:\n        ssl.SSLError: If SSL/TLS connection fails\n        socket.error: If network connection fails\n        ValueError: If certificate validation fails\n    \n    Security: \n    - Validates SSL certificates including hostname verification (CWE-295, CWE-297)\n    - Enforces TLS 1.2+ (CWE-327)\n    - Implements connection timeout to prevent resource exhaustion\n    """
    # Validate inputs
    if not hostname or not isinstance(hostname, str):
        raise ValueError("Hostname must be a non-empty string")
    
    if not isinstance(port, int) or port < 1 or port > 65535:
        raise ValueError("Port must be between 1 and 65535")
    
    if not isinstance(timeout, (int, float)) or timeout <= 0 or timeout > 300:
        raise ValueError("Timeout must be between 0 and 300 seconds")
    
    # Create secure SSL context
    context = create_secure_context()
    
    # Create raw socket with timeout
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    
    ssl_sock = None
    try:
        # Connect to server
        sock.connect((hostname, port))
        
        # Wrap socket with SSL/TLS - hostname verification is automatic (CWE-297)
        ssl_sock = context.wrap_socket(sock, server_hostname=hostname)
        
        # Get and validate peer certificate (CWE-295)
        cert = ssl_sock.getpeercert()
        if not cert:
            raise ValueError("Server did not provide a certificate")
        
        # Verify certificate subject matches hostname
        ssl.match_hostname(cert, hostname)
        
        # Extract certificate information for logging (no sensitive data)
        cert_info = {
            "subject": dict(x[0] for x in cert.get("subject", [])),
            "issuer": dict(x[0] for x in cert.get("issuer", [])),
            "version": cert.get("version"),
            "serialNumber": cert.get("serialNumber"),
            "notBefore": cert.get("notBefore"),
            "notAfter": cert.get("notAfter"),
            "protocol": ssl_sock.version(),
            "cipher": ssl_sock.cipher()
        }
        
        return ssl_sock, cert_info
        
    except (ssl.SSLError, socket.error, ValueError) as e:
        # Clean up on error
        if ssl_sock:
            try:
                ssl_sock.close()
            except Exception:
                pass
        else:
            try:
                sock.close()
            except Exception:
                pass
        raise


def send_https_request(
    url: str, 
    request_path: str = "/"
) -> Tuple[int, str]:
    """\n    Send an HTTPS GET request and return response.\n    \n    Args:\n        url: Server URL (e.g., "https://example.com")\n        request_path: Path to request (default: "/")\n    \n    Returns:\n        Tuple of (status_code, response_body)\n    \n    Security: Uses secure connection establishment with full certificate validation.\n    """
    # Parse and validate URL
    hostname, port, _ = parse_server_url(url)
    
    # Validate request path to prevent injection
    if not request_path or not isinstance(request_path, str):
        request_path = "/"
    
    if len(request_path) > 2048:
        raise ValueError("Request path exceeds maximum length")
    
    # Establish secure connection
    ssl_sock, cert_info = establish_secure_connection(hostname, port)
    
    try:
        # Construct HTTP request with explicit headers
        request = (
            f"GET {request_path} HTTP/1.1\\r\\n"
            f"Host: {hostname}\\r\\n"
            f"User-Agent: SecureClient/1.0\\r\\n"
            f"Connection: close\\r\\n"
            f"\\r\\n"
        )
        
        # Send request
        ssl_sock.sendall(request.encode("utf-8"))
        
        # Receive response with size limit to prevent memory exhaustion
        response_parts = []
        total_size = 0
        max_size = 10 * 1024 * 1024  # 10 MB limit
        
        while True:
            chunk = ssl_sock.recv(4096)
            if not chunk:
                break
            
            total_size += len(chunk)
            if total_size > max_size:
                raise ValueError("Response exceeds maximum size limit")
            
            response_parts.append(chunk)
        
        response = b"".join(response_parts).decode("utf-8", errors="replace")
        
        # Parse status code
        status_code = 0
        if response:
            first_line = response.split("\\r\\n")[0]
            parts = first_line.split()
            if len(parts) >= 2:
                try:
                    status_code = int(parts[1])
                except (ValueError, IndexError):
                    status_code = 0
        
        return status_code, response
        
    finally:
        # Always close the connection
        try:
            ssl_sock.close()
        except Exception:
            pass


def main() -> int:
    """\n    Main function with test cases demonstrating secure SSL/TLS connections.\n    \n    Returns:\n        Exit code (0 for success)\n    """
    print("Secure SSL/TLS Connection Test Cases")
    print("=" * 60)
    
    # Test case 1: Connect to a well-known HTTPS server
    print("\\nTest 1: Connecting to https://www.example.com")
    try:
        hostname, port, _ = parse_server_url("https://www.example.com")
        ssl_sock, cert_info = establish_secure_connection(hostname, port)
        print(f"✓ Connected successfully")
        print(f"  Protocol: {cert_info['protocol']}")
        print(f"  Cipher: {cert_info['cipher'][0]}")
        print(f"  Certificate Subject: {cert_info['subject'].get('commonName', 'N/A')}")
        ssl_sock.close()
    except Exception as e:
        print(f"✗ Failed: {type(e).__name__}: {e}")
    
    # Test case 2: Full HTTPS GET request
    print("\\nTest 2: HTTPS GET request to https://www.example.com")
    try:
        status_code, response = send_https_request("https://www.example.com", "/")
        print(f"✓ Request completed")
        print(f"  Status Code: {status_code}")
        print(f"  Response Length: {len(response)} bytes")
    except Exception as e:
        print(f"✗ Failed: {type(e).__name__}: {e}")
    
    # Test case 3: Invalid URL (should fail)
    print("\\nTest 3: Invalid URL (http instead of https)")
    try:
        hostname, port, _ = parse_server_url("http://www.example.com")
        print(f"✗ Should have failed but didn't")
    except ValueError as e:
        print(f"✓ Correctly rejected: {e}")
    
    # Test case 4: Invalid hostname (should fail)
    print("\\nTest 4: Invalid hostname")
    try:
        ssl_sock, cert_info = establish_secure_connection("", 443)
        print(f"✗ Should have failed but didn't")
    except ValueError as e:
        print(f"✓ Correctly rejected: {e}")
    
    # Test case 5: Invalid port (should fail)
    print("\\nTest 5: Invalid port number")
    try:
        ssl_sock, cert_info = establish_secure_connection("www.example.com", 99999)
        print(f"✗ Should have failed but didn't")
    except ValueError as e:
        print(f"✓ Correctly rejected: {e}")
    
    print("\\n" + "=" * 60)
    print("All test cases completed")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
