import socket
import ssl
from typing import Optional

def create_ssl_ipv6_socket(host: str, port: int) -> ssl.SSLSocket:
    """
    Creates and connects an SSL client socket over IPv6.

    This function uses ssl.create_default_context() to ensure secure defaults,
    including certificate validation and hostname checking.

    Args:
        host: The hostname to connect to.
        port: The port number to connect to.

    Returns:
        The connected ssl.SSLSocket object.

    Raises:
        ValueError: If the port is out of the valid range (1-65535).
        IOError: If the connection fails for any reason (DNS, network, SSL).
    """
    if not (1 <= port <= 65535):
        raise ValueError(f"Port {port} is out of valid range (1-65535)")

    # create_default_context() provides secure settings:
    # - It requires certificate validation (CERT_REQUIRED).
    # - It enables hostname checking.
    # - It tries to select reasonably secure protocol and cipher settings.
    context = ssl.create_default_context()
    
    # Create a raw TCP socket with the IPv6 address family.
    # The OS will handle resolving the hostname to an IPv6 address.
    raw_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    raw_socket.settimeout(5.0)
    
    # Wrap the socket with SSL context.
    # The server_hostname argument is crucial for Server Name Indication (SNI)
    # and for hostname checking.
    ssock = context.wrap_socket(raw_socket, server_hostname=host)
    
    try:
        ssock.connect((host, port))
    except (socket.error, ssl.SSLError, TimeoutError) as e:
        ssock.close()
        raise IOError(f"Failed to connect to {host}:{port}. Reason: {e}") from e
    
    return ssock

def main():
    """Main function with test cases."""
    test_cases = [
        ("google.com", 443),
        ("ietf.org", 443),
        ("wikipedia.org", 443),
        ("thishostdoesnotexist12345.com", 443),
        ("google.com", 99999) # Invalid port connection test
    ]

    for i, (host, port) in enumerate(test_cases):
        print(f"--- Test Case {i + 1}: Connecting to {host}:{port} over IPv6 ---")
        try:
            # Use a 'with' statement to ensure the socket is properly closed.
            with create_ssl_ipv6_socket(host, port) as ssock:
                print(f"Successfully connected to {ssock.getpeername()}")
                print(f"SSL Protocol: {ssock.version()}")
                print(f"Cipher Suite: {ssock.cipher()}")

                # Example: Send a simple HTTP GET request
                request = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
                ssock.sendall(request.encode('utf-8'))

                # Read the first line of the response
                response = ssock.recv(1024)
                first_line = response.split(b'\r\n')[0]
                print(f"Server response (first line): {first_line.decode('utf-8')}")

        except (IOError, ValueError, ssl.SSLCertVerificationError, socket.gaierror) as e:
            print(f"Failed to connect or communicate. Reason: {e}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
        
        print()

if __name__ == "__main__":
    main()