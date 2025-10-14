import socket
import ssl
import hashlib

def check_certificate_hash(hostname, port, known_hash):
    """
    Establishes a TLS connection, retrieves the server's certificate,
    and compares its SHA-256 hash with a known hash.

    :param hostname: The hostname to connect to.
    :param port: The port to connect to (usually 443 for HTTPS).
    :param known_hash: The expected SHA-256 hash of the certificate in hex.
    :return: True if the hash matches, False otherwise.
    """
    try:
        # Create a default SSL context.
        context = ssl.create_default_context()
        
        # Connect to the server
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as sslsock:
                # Get the certificate in DER format (binary)
                der_cert = sslsock.getpeercert(binary_form=True)
                if not der_cert:
                    return False

                # Calculate SHA-256 hash of the DER-encoded certificate
                calculated_hash = hashlib.sha256(der_cert).hexdigest()

                # Case-insensitive comparison
                return known_hash.lower() == calculated_hash.lower()
    except (socket.error, ssl.SSLError, socket.gaierror, socket.timeout) as e:
        # Any exception during connection or handshake indicates failure.
        # print(f"Error checking {hostname}: {e}")
        return False

def main():
    """Main function with test cases."""
    # The SHA-256 hash of the certificate for sha256.badssl.com
    correct_hash = "42a3219451add031a017243a05c45b882d9d1502425576a8049e7b39920194eb"
    incorrect_hash = "0000000000000000000000000000000000000000000000000000000000000000"

    print("--- Running Python Test Cases ---")

    # Test Case 1: Success - Correct host and correct hash
    test1 = check_certificate_hash("sha256.badssl.com", 443, correct_hash)
    print(f"Test 1 (Success): {'Passed' if test1 else 'Failed'}")

    # Test Case 2: Failure - Correct host but incorrect hash
    test2 = check_certificate_hash("sha256.badssl.com", 443, incorrect_hash)
    print(f"Test 2 (Failure - Wrong Hash): {'Passed' if not test2 else 'Failed'}")

    # Test Case 3: Failure - Wrong host
    test3 = check_certificate_hash("google.com", 443, correct_hash)
    print(f"Test 3 (Failure - Wrong Host): {'Passed' if not test3 else 'Failed'}")

    # Test Case 4: Failure - Non-existent host
    test4 = check_certificate_hash("nonexistent.domain.local", 443, correct_hash)
    print(f"Test 4 (Failure - Non-existent Host): {'Passed' if not test4 else 'Failed'}")

    # Test Case 5: Failure - Host does not support SSL on the port
    test5 = check_certificate_hash("neverssl.com", 443, correct_hash)
    print(f"Test 5 (Failure - No SSL): {'Passed' if not test5 else 'Failed'}")

if __name__ == "__main__":
    main()