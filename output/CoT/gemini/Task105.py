import socket
import ssl

def establish_tls_connection(host, port):
    """
    Establishes a secure SSL/TLS connection to a remote server.

    Args:
        host: The hostname or IP address of the server.
        port: The port number of the server.

    Returns:
        True if the connection was successfully established, False otherwise.
    """
    # ssl.create_default_context() is the recommended, secure way to create a context.
    # It loads default CA certificates, enables hostname checking, and tries to
    # select secure protocol and cipher settings.
    context = ssl.create_default_context()

    # We could be more explicit about protocol versions if needed:
    # context.minimum_version = ssl.TLSVersion.TLSv1_2

    print(f"Attempting to connect to {host}:{port} over TLS...")

    try:
        # Create a standard TCP socket
        with socket.create_connection((host, port), timeout=10) as sock:
            # Wrap the socket with the SSL context.
            # The 'server_hostname' argument is crucial for Server Name Indication (SNI)
            # and for matching the hostname against the certificate.
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                print("TLS connection established successfully!")
                print(f"Connected to: {ssock.getpeername()}")
                print(f"Using protocol: {ssock.version()}")
                print(f"Using cipher: {ssock.cipher()}")
                
                # Optional: Send a simple HTTP request to verify
                request = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
                ssock.sendall(request.encode('utf-8'))
                
                # Receive a small part of the response
                response = ssock.recv(1024)
                if response:
                    print("Successfully received response data.")
                
                return True

    except ssl.SSLCertVerificationError as e:
        print(f"ERROR: Certificate verification failed for {host}:{port}.")
        print(f"Reason: {e}")
        return False
    except ssl.SSLError as e:
        print(f"ERROR: An SSL error occurred with {host}:{port}.")
        print(f"Reason: {e}")
        return False
    except socket.gaierror as e:
        print(f"ERROR: Hostname could not be resolved for {host}.")
        print(f"Reason: {e}")
        return False
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        print(f"ERROR: Could not connect to {host}:{port}.")
        print(f"Reason: {e}")
        return False


if __name__ == "__main__":
    print("--- Running SSL/TLS Connection Tests ---")

    # Test Case 1: Successful connection to a major site
    print("\n[Test Case 1: www.google.com]")
    result1 = establish_tls_connection("www.google.com", 443)
    print(f"Test 1 Result: {'SUCCESS' if result1 else 'FAILURE'}")

    # Test Case 2: Successful connection to another major site
    print("\n[Test Case 2: www.github.com]")
    result2 = establish_tls_connection("www.github.com", 443)
    print(f"Test 2 Result: {'SUCCESS' if result2 else 'FAILURE'}")

    # Test Case 3: Connection to a server with an expired certificate
    # This should fail certificate validation.
    print("\n[Test Case 3: expired.badssl.com]")
    result3 = establish_tls_connection("expired.badssl.com", 443)
    print(f"Test 3 Result: {'SUCCESS (Correctly failed)' if not result3 else 'FAILURE (Incorrectly succeeded)'}")

    # Test Case 4: Connection to a server with a mismatched hostname in the certificate
    # This should fail certificate validation.
    print("\n[Test Case 4: wrong.host.badssl.com]")
    result4 = establish_tls_connection("wrong.host.badssl.com", 443)
    print(f"Test 4 Result: {'SUCCESS (Correctly failed)' if not result4 else 'FAILURE (Incorrectly succeeded)'}")

    # Test Case 5: Connection to a non-existent domain
    # This should fail at the DNS resolution or TCP connection stage.
    print("\n[Test Case 5: non-existent-domain-for-testing-123.com]")
    result5 = establish_tls_connection("non-existent-domain-for-testing-123.com", 443)
    print(f"Test 5 Result: {'SUCCESS (Correctly failed)' if not result5 else 'FAILURE (Incorrectly succeeded)'}")

    print("\n--- All tests completed. ---")