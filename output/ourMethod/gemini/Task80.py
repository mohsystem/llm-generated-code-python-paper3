import socket
import ssl
from typing import Optional

def create_ipv6_ssl_client_socket(host: str, port: int) -> Optional[ssl.SSLSocket]:
    """
    Creates a client SSL socket using IPv6, connects to a host and port, and returns it.

    This function enforces modern security standards for TLS connections, including
    requiring TLS 1.2 or higher, certificate validation, and hostname checking.

    Args:
        host: The hostname or IPv6 address to connect to.
        port: The port number to connect to.

    Returns:
        An established ssl.SSLSocket object on success, or None on failure.
    """
    # Rule #6: Ensure all input is validated.
    if not isinstance(host, str) or not host:
        print("Error: Host must be a non-empty string.")
        return None
    if not isinstance(port, int) or not (1 <= port <= 65535):
        print(f"Error: Port must be an integer between 1 and 65535, but got {port}.")
        return None

    # Rule #10: Use vetted cryptographic libraries and modern algorithms.
    # Rule #4, #5: Ensure proper validation of SSL/TLS certificates and hostnames.
    try:
        # Start with recommended security settings
        context = ssl.create_default_context()
        
        # Explicitly set options for clarity, though they are defaults
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        # Rule #9: Enforce strong, industry-standard protocols.
        # Disable insecure protocols like SSLv2, SSLv3, TLSv1.0, TLSv1.1
        # The recommended way is to set a minimum TLS version.
        if hasattr(ssl, "TLSVersion"):  # Available in Python 3.7+
            context.minimum_version = ssl.TLSVersion.TLSv1_2
        else: # Fallback for older Python versions
            context.options |= getattr(ssl, "OP_NO_SSLv2", 0)
            context.options |= getattr(ssl, "OP_NO_SSLv3", 0)
            context.options |= getattr(ssl, "OP_NO_TLSv1", 0)
            context.options |= getattr(ssl, "OP_NO_TLSv1_1", 0)

    except Exception as e:
        print(f"Error creating SSL context: {e}")
        return None

    ssl_socket = None
    try:
        # Resolve hostname to an IPv6 address. This will raise socket.gaierror
        # if no IPv6 address (AAAA record) is found.
        addrinfo = socket.getaddrinfo(host, port, socket.AF_INET6, socket.SOCK_STREAM)
        family, socktype, proto, _, sockaddr = addrinfo[0]

        # Create the raw socket
        raw_socket = socket.socket(family, socktype, proto)

        # Wrap the socket with SSL/TLS context.
        # Rule #5: Pass server_hostname for SNI and hostname verification.
        ssl_socket = context.wrap_socket(raw_socket, server_hostname=host)
        
        # Establish connection and perform TLS handshake
        ssl_socket.connect(sockaddr)
        
        print(f"Successfully connected to {host}:{port} over IPv6.")
        print(f"Using TLS version: {ssl_socket.version()}")
        
        return ssl_socket

    # Rule #14: Ensure that all exceptions are caught and handled.
    except ssl.SSLCertVerificationError as e:
        print(f"SSL Certificate Verification Error for {host}: {e.reason}")
        if ssl_socket:
            ssl_socket.close()
        return None
    except socket.gaierror as e:
        print(f"Address resolution error for host '{host}' (is IPv6 available?): {e}")
        # No socket to close here as it would fail before creation
        return None
    except (socket.error, ConnectionRefusedError, TimeoutError, OSError) as e:
        print(f"Socket connection error for {host}:{port}: {e}")
        if ssl_socket:
            ssl_socket.close()
        return None
    except Exception as e:
        print(f"An unexpected error occurred for {host}:{port}: {e}")
        if ssl_socket:
            ssl_socket.close()
        return None


if __name__ == '__main__':
    # A list of test cases to demonstrate the function's behavior.
    test_cases = [
        # 1. Valid host with IPv6 support. Should succeed.
        ("google.com", 443),
        # 2. Host with a self-signed certificate. Should fail certificate verification.
        ("self-signed.badssl.com", 443),
        # 3. Non-existent host. Should fail address resolution.
        ("nonexistent-domain-for-testing-12345.com", 443),
        # 4. Valid host, but a port that is likely closed. Should fail with connection refused/timeout.
        ("google.com", 12345),
        # 5. Invalid port number. Should fail input validation.
        ("google.com", 99999),
        # 6. A host that may not have an IPv6 record. Should fail address resolution for IPv6.
        ("ipv4.google.com", 443)
    ]

    for i, (host, port) in enumerate(test_cases, 1):
        print(f"\n--- Test Case {i}: Connecting to {host}:{port} ---")
        sock = create_ipv6_ssl_client_socket(host, port)
        
        if sock:
            print("Connection successful. Socket details:")
            print(f"  Peer: {sock.getpeername()}")
            print(f"  Cipher: {sock.cipher()}")
            
            # The caller is responsible for closing the socket.
            # Here, we'll just close it immediately after verification.
            sock.close()
            print("  Socket closed.")
        else:
            print("Connection failed as expected or due to an error.")