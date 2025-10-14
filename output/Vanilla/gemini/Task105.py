import ssl
import socket

def establish_ssl_connection(host, port):
    """
    Establishes a secure SSL/TLS connection to a remote server.
    :param host: The hostname of the server.
    :param port: The port number of the server.
    :return: True if the connection was successful, False otherwise.
    """
    print(f"Attempting to connect to {host}:{port}...")
    # Create a default SSL context. This provides good security defaults.
    context = ssl.create_default_context()

    try:
        # Create a standard TCP socket and wrap it with the SSL context
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                print(f"Successfully connected to {host}:{port}")
                print("SSL Connection Info:")
                print(f"\tProtocol: {ssock.version()}")
                print(f"\tCipher: {ssock.cipher()}")
                
                # Connection is automatically closed by 'with' statements
                return True
    except (socket.gaierror, socket.error, ssl.SSLError, ConnectionRefusedError, TimeoutError) as e:
        print(f"Failed to connect to {host}:{port}")
        print(f"Error: {e}")
        return False
    finally:
        print("----------------------------------------")


if __name__ == "__main__":
    # 5 Test Cases
    establish_ssl_connection("google.com", 443)
    establish_ssl_connection("github.com", 443)
    establish_ssl_connection("cloudflare.com", 443)
    establish_ssl_connection("amazon.com", 443)
    establish_ssl_connection("nonexistent-host-for-testing.com", 443) # Failure case