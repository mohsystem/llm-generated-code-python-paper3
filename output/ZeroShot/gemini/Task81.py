import ssl
import hashlib
import socket

def check_certificate_hash(hostname, expected_hash, port=443):
    """
    Connects to a given host, retrieves its SSL certificate, and checks
    if its SHA-256 hash matches the expected hash.

    :param hostname: The hostname of the server (e.g., "example.com").
    :param expected_hash: The expected SHA-256 hash of the certificate as a hex string.
    :param port: The port to connect to (default is 443 for HTTPS).
    :return: True if the hash matches, False otherwise.
    """
    if not hostname or not expected_hash:
        return False
        
    try:
        # Get certificate from server in PEM format
        pem_cert = ssl.get_server_certificate((hostname, port))
        
        # Convert PEM to DER format (binary)
        der_cert = ssl.PEM_cert_to_DER_cert(pem_cert)
        
        # Calculate SHA-256 hash of the DER-encoded certificate
        sha256 = hashlib.sha256()
        sha256.update(der_cert)
        actual_hash = sha256.hexdigest()
        
        return actual_hash.lower() == expected_hash.lower()

    except (socket.gaierror, socket.timeout, ConnectionRefusedError, ssl.SSLError, OSError) as e:
        print(f"Error connecting to {hostname}: {e}")
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return False

def main():
    # NOTE: Certificate hashes change when certificates are renewed.
    # These test cases use a hash for example.com that was valid at the time of writing.
    # It may need to be updated. You can get the current hash with:
    # openssl s_client -connect example.com:443 -showcerts < /dev/null 2>/dev/null | openssl x509 -outform DER | openssl dgst -sha256 -hex
    
    example_com_host = "example.com"
    # This hash is for the example.com certificate and may change over time.
    correct_example_com_hash = "3469e34a6058e5e959725f463385623089d7b901e0a9d8329b35e69e061517a9"
    incorrect_hash = "0000000000000000000000000000000000000000000000000000000000000000"

    # Test Case 1: Correct host and correct hash
    print(f"Test Case 1 (Correct): {'Passed' if check_certificate_hash(example_com_host, correct_example_com_hash) else 'Failed'}")

    # Test Case 2: Correct host and incorrect hash
    print(f"Test Case 2 (Incorrect Hash): {'Passed' if not check_certificate_hash(example_com_host, incorrect_hash) else 'Failed'}")

    # Test Case 3: Different host with the first host's hash
    print(f"Test Case 3 (Mismatched Host): {'Passed' if not check_certificate_hash('google.com', correct_example_com_hash) else 'Failed'}")
    
    # Test Case 4: Non-existent host
    print(f"Test Case 4 (Invalid Host): {'Passed' if not check_certificate_hash('non-existent-domain-12345.com', correct_example_com_hash) else 'Failed'}")
    
    # Test Case 5: Using a different port (should fail if not serving the same cert)
    # This will likely fail due to connection error rather than hash mismatch.
    print(f"Test Case 5 (Wrong Port): {'Passed' if not check_certificate_hash(example_com_host, correct_example_com_hash, port=80) else 'Failed'}")

if __name__ == "__main__":
    main()