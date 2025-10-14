import ssl
import socket

def establish_secure_connection(host, port):
    """
    Establishes a secure SSL/TLS connection to a remote server.

    :param host: The hostname of the server.
    :param port: The port number of the server.
    :return: True if the connection was successful, False otherwise.
    """
    # Create a default SSL context. This provides a good balance of security and
    # compatibility. It enables hostname checking and certificate validation by default.
    context = ssl.create_default_context()
    
    # Optionally, be more strict about the TLS version
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    try:
        # Create a standard TCP socket and connect
        with socket.create_connection((host, port), timeout=10) as sock:
            # Wrap the socket with the SSL context. server_hostname is crucial for SNI.
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                print(f"Successfully connected to {host}:{port}")
                print("SSL Session Info:")
                print(f"\tProtocol: {ssock.version()}")
                print(f"\tCipher Suite: {ssock.cipher()[0]}")
                peer_cert = ssock.getpeercert()
                if peer_cert and 'subject' in peer_cert:
                    subject_str = ', '.join(f"{k}={v}" for k, v in (item[0] for item in peer_cert['subject']))
                    print(f"\tPeer Principal: {subject_str}")
                return True
    except ssl.SSLCertVerificationError as e:
        print(f"SSL Certificate Verification Error for {host}:{port}. Error: {e}")
    except ssl.SSLError as e:
        print(f"SSL Error for {host}:{port}. Error: {e}")
    except socket.gaierror:
        print(f"Could not resolve host: {host}")
    except socket.error as e:
        print(f"Socket error when connecting to {host}:{port}. Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred for {host}:{port}. Error: {e}")
    
    return False

def main():
    test_cases = [
        ("google.com", 443),
        ("github.com", 443),
        ("expired.badssl.com", 443),
        ("wrong.host.badssl.com", 443),
        ("nonexistent-domain-xyz123.com", 443)
    ]

    for i, (host, port) in enumerate(test_cases, 1):
        print(f"\n--- Test Case {i}: Connecting to {host}:{port} ---")
        success = establish_secure_connection(host, port)
        print(f"Connection status: {'SUCCESS' if success else 'FAILURE'}")
        print("----------------------------------------------------")

if __name__ == "__main__":
    main()