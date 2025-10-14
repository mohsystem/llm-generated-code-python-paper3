import socket
import ssl

def create_ipv6_ssl_client_socket(host, port):
    """
    Creates an SSL client socket using IPv6 and TCP.

    :param host: The hostname to connect to.
    :param port: The port to connect to.
    :return: The established SSL socket, or None if connection fails.
    """
    context = ssl.create_default_context()
    addr_info = None
    
    try:
        # Get address info, restricting to IPv6
        addr_info = socket.getaddrinfo(host, port, family=socket.AF_INET6, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        print(f"Error getting address info for {host}: {e}")
        return None

    if not addr_info:
        print(f"No IPv6 address found for host: {host}")
        return None

    # Use the first address returned
    family, socktype, proto, _, sockaddr = addr_info[0]
    
    try:
        # Create a raw socket
        sock = socket.socket(family, socktype, proto)
        # Wrap the socket with SSL
        ssl_sock = context.wrap_socket(sock, server_hostname=host)
        # Connect to the server
        ssl_sock.connect(sockaddr)
        return ssl_sock
    except Exception as e:
        print(f"Failed to connect to {host}:{port} over IPv6: {e}")
        return None

if __name__ == "__main__":
    hosts = ["google.com", "facebook.com", "ipv6.google.com", "wikipedia.org", "example.com"]
    port = 443

    for host in hosts:
        print(f"--- Testing connection to {host}:{port} ---")
        ssl_socket = None
        try:
            ssl_socket = create_ipv6_ssl_client_socket(host, port)
            if ssl_socket:
                print(f"Successfully connected to {host} over IPv6.")
                print(f"Remote Address: {ssl_socket.getpeername()}")
                print(f"Cipher: {ssl_socket.cipher()}")
            else:
                print(f"Failed to connect to {host} over IPv6.")
        except Exception as e:
            print(f"An exception occurred for host {host}: {e}")
        finally:
            if ssl_socket:
                ssl_socket.close()
                print("Socket closed.")
        print()