import socket
import ssl
from typing import Tuple

def establish_secure_connection(host: str, port: int) -> bool:
    """
    Establishes a secure SSL/TLS connection to a remote server.

    Args:
        host: The hostname of the server.
        port: The port number of the server.

    Returns:
        True if the connection was successful and secure, False otherwise.
    """
    if not host or not (0 < port < 65536):
        print(f"Error: Invalid host or port provided.")
        return False
        
    # create_default_context() provides a secure-by-default context:
    # - It requires certificate validation (verify_mode=CERT_REQUIRED).
    # - It enables hostname checking (check_hostname=True).
    # - It loads the system's default trusted CA certificates.
    context = ssl.create_default_context()
    
    try:
        # Create a standard TCP socket
        with socket.create_connection((host, port), timeout=10) as sock:
            # Wrap the socket with the SSL context
            # server_hostname is used for hostname checking (SNI)
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                print(f"Successfully connected to {host}:{port}")
                print(f"SSL/TLS Protocol: {ssock.version()}")
                print(f"Cipher Suite: {ssock.cipher()[0]}")
                
                # Get peer certificate information
                cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert['subject'])
                print(f"Peer Certificate CN: {subject.get('commonName')}")
                
                # Example: Send a simple HTTP GET request
                request = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
                ssock.sendall(request.encode('utf-8'))

                # Read the response
                response = ssock.recv(4096).decode('utf-8', errors='ignore')
                print("\n--- Server Response (first few lines) ---")
                print('\n'.join(response.splitlines()[:5]))
                print("---------------------------------------\n")

                return True
                
    except ssl.SSLCertVerificationError as e:
        print(f"SSL Certificate Verification Error for {host}:{port}: {e}")
        return False
    except ssl.SSLError as e:
        print(f"SSL Error for {host}:{port}: {e}")
        return False
    except socket.gaierror as e:
        print(f"Hostname Resolution Error for {host}: {e}")
        return False
    except socket.timeout:
        print(f"Connection timed out for {host}:{port}")
        return False
    except ConnectionRefusedError:
        print(f"Connection refused by {host}:{port}")
        return False
    except OSError as e:
        print(f"OS Error for {host}:{port}: {e}")
        return False

def main():
    test_cases = [
        ("www.google.com", 443),
        ("www.cloudflare.com", 443),
        ("expired.badssl.com", 443),
        ("wrong.host.badssl.com", 443),
        ("self-signed.badssl.com", 443),
    ]

    for host, port in test_cases:
        print(f"--- Testing connection to {host} ---")
        success = establish_secure_connection(host, port)
        print(f"Connection status: {'SUCCESS' if success else 'FAILURE'}")
        print("--------------------------------------\n")


if __name__ == "__main__":
    main()