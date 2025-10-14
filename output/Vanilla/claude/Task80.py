
import socket
import ssl

def create_ssl_client_socket(host, port):
    # Create a socket with IPv6 and TCP
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    
    # Wrap the socket with SSL
    context = ssl.create_default_context()
    ssl_sock = context.wrap_socket(sock, server_hostname=host)
    
    # Connect to the specified host and port
    try:
        # Try to resolve and connect using IPv6
        ssl_sock.connect((host, port))
    except socket.gaierror:
        # If IPv6 fails, try with IPv4-mapped IPv6 address
        sock.close()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_sock = context.wrap_socket(sock, server_hostname=host)
        ssl_sock.connect((host, port))
    
    return ssl_sock

if __name__ == "__main__":
    # Test cases
    test_hosts = [
        "www.google.com",
        "www.github.com",
        "www.amazon.com",
        "www.microsoft.com",
        "www.apple.com"
    ]
    test_ports = [443, 443, 443, 443, 443]
    
    for i, (host, port) in enumerate(zip(test_hosts, test_ports), 1):
        try:
            print(f"Test {i}: Connecting to {host}:{port}")
            ssl_socket = create_ssl_client_socket(host, port)
            print("Successfully connected!")
            print(f"Remote Address: {ssl_socket.getpeername()}")
            print(f"Local Address: {ssl_socket.getsockname()}")
            ssl_socket.close()
            print("Connection closed.\\n")
        except Exception as e:
            print(f"Failed to connect: {e}\\n")
