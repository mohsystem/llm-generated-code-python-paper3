import socket
import ssl

def create_ipv6_ssl_socket(host, port):
    """
    Creates a secure SSL client socket using IPv6 and connects to the specified host and port.

    Args:
        host: The hostname to connect to.
        port: The port number to connect to.

    Returns:
        The connected SSLSocket object, or None if the connection fails.
    """
    try:
        # 1. Resolve hostname to IPv6 addresses
        # This will raise socket.gaierror if no IPv6 address is found
        addr_info = socket.getaddrinfo(host, port, socket.AF_INET6, socket.SOCK_STREAM)
        
        # We'll use the first address found
        family, socktype, proto, _, sockaddr = addr_info[0]
        print(f"Resolved {host} to IPv6 address: {sockaddr[0]}")
        
        # 2. Create a default SSL context.
        # This provides good security defaults: certificate validation, modern protocols.
        context = ssl.create_default_context()

        # 3. Create a standard TCP socket
        sock = socket.socket(family, socktype, proto)
        
        # 4. Wrap the socket with SSL context for a secure connection
        # The 'server_hostname' argument is crucial for SNI and certificate validation
        ssl_sock = context.wrap_socket(sock, server_hostname=host)
        
        # 5. Connect to the server
        ssl_sock.connect(sockaddr)
        
        print(f"SSL connection successful to {host}:{port}")
        print(f"Using protocol: {ssl_sock.version()}")
        return ssl_sock

    except socket.gaierror:
        print(f"Error: Could not resolve IPv6 address for host: {host}")
    except ConnectionRefusedError:
        print(f"Error: Connection refused by {host}:{port}")
    except ssl.SSLCertVerificationError as e:
        print(f"Error: SSL certificate verification failed for {host}. {e}")
    except Exception as e:
        print(f"An unexpected error occurred for {host}:{port}. {e}")
        
    return None

def main():
    # --- Test Cases ---
    test_cases = [
        ("google.com", 443),
        ("facebook.com", 443),
        ("wikipedia.org", 443),
        ("nonexistent.veryunlikelydomain.com", 443),
        ("google.com", 444), # Port where connection is likely refused
    ]

    for i, (host, port) in enumerate(test_cases):
        print(f"\n--- Test Case {i + 1}: Connecting to {host}:{port} ---")
        ssl_socket = None
        try:
            ssl_socket = create_ipv6_ssl_socket(host, port)
            if ssl_socket:
                print(f"Successfully connected to {host}:{port}")
                
                # Perform a simple HTTP GET to verify connection
                request = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
                ssl_socket.sendall(request.encode('utf-8'))
                
                response = ssl_socket.recv(1024).decode('utf-8', errors='ignore')
                print(f"Response from server: {response.splitlines()[0]}")

            else:
                print(f"Failed to connect to {host}:{port}")

        except Exception as e:
            print(f"Error during communication with {host}: {e}")
        finally:
            if ssl_socket:
                ssl_socket.close()

if __name__ == "__main__":
    main()