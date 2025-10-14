
import socket
import ssl

def create_ssl_client_socket(host, port):
    """\n    Creates an SSL client socket using IPv6 and TCP protocol.\n    Connects to the specified host and port, and returns the established socket.\n    """
    try:
        # Create a TCP/IP socket with IPv6
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.settimeout(10)
        
        # Wrap the socket with SSL
        context = ssl.create_default_context()
        ssl_socket = context.wrap_socket(sock, server_hostname=host)
        
        # Try to resolve and connect using IPv6
        try:
            # Get IPv6 address info
            addr_info = socket.getaddrinfo(host, port, socket.AF_INET6, socket.SOCK_STREAM)
            if addr_info:
                ipv6_addr = addr_info[0][4]
                ssl_socket.connect(ipv6_addr)
            else:
                raise Exception("No IPv6 address found")
        except:
            # Fallback: try direct connection
            ssl_socket.connect((host, port))
        
        return ssl_socket
    except Exception as e:
        raise Exception(f"Failed to create SSL socket: {str(e)}")

def main():
    test_cases = [
        ("www.google.com", 443),
        ("www.github.com", 443),
        ("www.mozilla.org", 443),
        ("www.wikipedia.org", 443),
        ("www.cloudflare.com", 443)
    ]
    
    print("Testing SSL Client Socket with IPv6/TCP:")
    print("=========================================\\n")
    
    for i, (host, port) in enumerate(test_cases, 1):
        print(f"Test Case {i}:")
        print(f"Host: {host}, Port: {port}")
        
        try:
            ssl_socket = create_ssl_client_socket(host, port)
            print("Status: Connected successfully")
            print(f"Local Address: {ssl_socket.getsockname()}")
            print(f"Remote Address: {ssl_socket.getpeername()}")
            print(f"Protocol: {ssl_socket.version()}")
            ssl_socket.close()
            print("Socket closed successfully")
        except Exception as e:
            print(f"Status: Failed - {str(e)}")
        print()

if __name__ == "__main__":
    main()
