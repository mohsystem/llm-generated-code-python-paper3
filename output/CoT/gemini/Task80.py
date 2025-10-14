import socket
import ssl
from typing import Optional

def create_ssl_ipv6_client_socket(host: str, port: int) -> Optional[ssl.SSLSocket]:
    """
    Creates an SSL client socket using IPv6 and TCP, connects to the specified host and port.

    This function explicitly resolves the hostname to an IPv6 address.

    Args:
        host: The hostname to connect to.
        port: The port number to connect to.

    Returns:
        The established SSL socket, or None on failure.
    """
    ipv6_address_info = None
    try:
        # Resolve the hostname to get address info, filtering for AF_INET6
        addr_infos = socket.getaddrinfo(host, port, family=socket.AF_INET6, type=socket.SOCK_STREAM)
        if not addr_infos:
            print(f"Error: Could not resolve {host} to an IPv6 address.")
            return None
        # Use the first result
        ipv6_address_info = addr_infos[0]
    except socket.gaierror as e:
        print(f"Error resolving address for {host}: {e}")
        return None

    # create_default_context() provides secure defaults:
    # - enables certificate validation (CERT_REQUIRED)
    # - enables hostname checking
    # - loads default CA certificates
    context = ssl.create_default_context()
    
    family, socktype, proto, _, sockaddr = ipv6_address_info
    
    try:
        # Create a plain TCP/IPv6 socket
        plain_socket = socket.socket(family, socktype, proto)
        
        # Connect the plain socket first
        plain_socket.connect(sockaddr)

        # Wrap the socket with SSL/TLS.
        # server_hostname is crucial for SNI and proper certificate validation.
        ssl_socket = context.wrap_socket(plain_socket, server_hostname=host)
        
        return ssl_socket
    except (socket.error, ssl.SSLError, TimeoutError) as e:
        print(f"Failed to connect to {host} [{sockaddr[0]}]: {e}")
        return None

def main():
    """Main function with test cases."""
    test_hosts = [
        "google.com",
        "www.facebook.com",
        "ipv6.google.com",
        "www.ietf.org",
        "badssl.com"
    ]
    port = 443

    for host in test_hosts:
        print(f"--- Testing connection to {host}:{port} ---")
        ssl_socket = None
        try:
            ssl_socket = create_ssl_ipv6_client_socket(host, port)
            if ssl_socket:
                print(f"Successfully connected to {host} at {ssl_socket.getpeername()[0]}")
                print(f"SSL/TLS Protocol: {ssl_socket.version()}")
                print(f"Cipher Suite: {ssl_socket.cipher()[0]}")
                
                peer_cert = ssl_socket.getpeercert()
                subject = dict(x[0] for x in peer_cert.get('subject', []))
                print(f"Peer CN: {subject.get('commonName', 'N/A')}")

        except Exception as e:
            print(f"An unexpected error occurred for {host}: {e}")
        finally:
            if ssl_socket:
                ssl_socket.close()
            print()

if __name__ == "__main__":
    main()