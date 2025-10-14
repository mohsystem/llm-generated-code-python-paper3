
import ssl
import socket
import re
from typing import Optional

def create_ssl_client_socket(host: str, port: int) -> ssl.SSLSocket:
    """\n    Creates an SSL client socket using IPv6 and TCP protocol.\n    \n    Args:\n        host: The hostname to connect to\n        port: The port number to connect to\n        \n    Returns:\n        An established SSL socket\n        \n    Raises:\n        ValueError: If input validation fails\n        ssl.SSLError: If SSL connection fails\n        OSError: If socket connection fails\n    """
    # Input validation
    if not host or not isinstance(host, str):
        raise ValueError("Host must be a non-empty string")
    
    if not isinstance(port, int) or port < 1 or port > 65535:
        raise ValueError("Port must be between 1 and 65535")
    
    # Sanitize host input - remove control characters
    host = re.sub(r'[\\x00-\\x1f\\x7f-\\x9f]', '', host)
    host = host.strip()
    
    if not host:
        raise ValueError("Host cannot be empty after sanitization")
    
    # Create SSL context with strong security settings
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    
    # Load default CA certificates for verification
    context.load_default_certs()
    
    # Require certificate verification
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    
    # Set minimum TLS version to 1.2
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    
    # Set strong cipher suites only
    context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:!aNULL:!MD5:!DSS:!DES:!3DES')
    
    # Try IPv6 first, fall back to IPv4 if necessary
    sock = None
    last_error = None
    
    try:
        # Get address information
        addr_info = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        
        # Sort to prefer IPv6
        addr_info.sort(key=lambda x: 0 if x[0] == socket.AF_INET6 else 1)
        
        for family, socktype, proto, canonname, sockaddr in addr_info:
            try:
                # Create socket
                sock = socket.socket(family, socktype, proto)
                sock.settimeout(10.0)  # 10 second timeout
                
                # Wrap socket with SSL
                ssl_sock = context.wrap_socket(sock, server_hostname=host)
                
                # Connect to the server
                ssl_sock.connect(sockaddr)
                
                # Verify the connection
                if ssl_sock.version() not in ['TLSv1.2', 'TLSv1.3']:
                    ssl_sock.close()
                    raise ssl.SSLError("Insecure TLS version")
                
                return ssl_sock
                
            except (socket.error, ssl.SSLError) as e:
                if sock:
                    sock.close()
                last_error = e
                continue
        
        # If we got here, all attempts failed
        if last_error:
            raise last_error
        else:
            raise OSError(f"Could not connect to {host}:{port}")
            
    except socket.gaierror as e:
        raise OSError(f"Failed to resolve host {host}: {e}")


def main():
    """Test the SSL socket creation with 5 test cases."""
    test_cases = [
        ("www.google.com", 443),
        ("www.github.com", 443),
        ("www.cloudflare.com", 443),
        ("www.amazon.com", 443),
        ("www.microsoft.com", 443)
    ]
    
    for host, port in test_cases:
        try:
            ssl_socket = create_ssl_client_socket(host, port)
            print(f"Successfully connected to {host}:{port}")
            print(f"Protocol: {ssl_socket.version()}")
            print(f"Cipher: {ssl_socket.cipher()[0]}")
            print("---")
            ssl_socket.close()
        except Exception as e:
            print(f"Failed to connect to {host}:{port} - {e}")


if __name__ == "__main__":
    main()
