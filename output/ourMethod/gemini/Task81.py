import ssl
import socket
import hashlib
from typing import Optional

def verify_certificate_hash(hostname: str, port: int, known_hash: str, hash_algo: str = 'sha256') -> bool:
    """
    Connects to a server, retrieves its SSL certificate, and verifies its hash.

    This function performs full SSL/TLS certificate validation, including
    checking the trust chain, expiration date, and hostname, before
    comparing the certificate's hash against a known value (pinning).

    Args:
        hostname: The server hostname.
        port: The server port.
        known_hash: The known hexadecimal hash of the certificate to check against.
        hash_algo: The hash algorithm to use (e.g., 'sha256').

    Returns:
        True if the certificate's hash matches the known hash, False otherwise.
        Returns False on any connection, SSL, or validation error.
    """
    if not hostname or not (1 <= port <= 65535):
        print("Error: Invalid hostname or port.")
        return False

    # Create a secure SSL context with default settings for certificate validation.
    # This enables hostname checking and certificate chain verification by default.
    context = ssl.create_default_context()

    # Enforce modern, secure TLS versions (TLS 1.2 and higher).
    # This follows security best practices by disabling outdated protocols.
    if hasattr(ssl, "TLSVersion"):  # Available in Python 3.10+
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    else:  # For older Python versions
        # Explicitly disable older, insecure protocols.
        context.options |= getattr(ssl, "OP_NO_SSLv2", 0)
        context.options |= getattr(ssl, "OP_NO_SSLv3", 0)
        context.options |= getattr(ssl, "OP_NO_TLSv1", 0)
        context.options |= getattr(ssl, "OP_NO_TLSv1_1", 0)

    try:
        # Establish a connection and wrap the socket with the SSL context.
        # The timeout prevents the program from hanging indefinitely.
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as sslsock:
                # Retrieve the peer's certificate in DER binary format.
                cert_der: Optional[bytes] = sslsock.getpeercert(binary_form=True)
                if not cert_der:
                    print(f"Error: Could not retrieve certificate from {hostname}")
                    return False

                # Calculate the hash of the DER-encoded certificate.
                hasher = hashlib.new(hash_algo)
                hasher.update(cert_der)
                calculated_hash = hasher.hexdigest()

                # Compare the calculated hash with the known, pinned hash.
                return calculated_hash.lower() == known_hash.lower()

    except socket.gaierror:
        print(f"Error: Hostname '{hostname}' could not be resolved.")
        return False
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        print(f"Error: Network error connecting to {hostname}:{port}: {e}")
        return False
    except ssl.SSLCertVerificationError as e:
        # This occurs if standard certificate validation fails (e.g., expired, self-signed).
        print(f"Error: SSL certificate verification failed for {hostname}: {e.reason}")
        return False
    except ssl.SSLError as e:
        print(f"Error: An SSL error occurred for {hostname}: {e}")
        return False
    except ValueError:
        print(f"Error: Unsupported hash algorithm '{hash_algo}'.")
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return False

if __name__ == '__main__':
    # --- Test Cases ---
    
    # Test Case 1: Valid certificate and matching hash.
    # badssl.com provides a test server with a certificate whose SHA-256 hash is known.
    host1 = "sha256.badssl.com"
    # This is the expected SHA-256 fingerprint for sha256.badssl.com's certificate.
    known_hash1 = "5f38459458485c5a019e1c1214e2a2202636a0480b1e32808c1f4e3f895c1c4f"
    print(f"1. Testing {host1} with correct hash...")
    result1 = verify_certificate_hash(host1, 443, known_hash1, 'sha256')
    print(f"   --> Result: {'Match' if result1 else 'No Match'} (Expected: Match)\n")

    # Test Case 2: Valid certificate but a non-matching hash.
    host2 = "google.com"
    known_hash2 = "0000000000000000000000000000000000000000000000000000000000000000"
    print(f"2. Testing {host2} with incorrect hash...")
    result2 = verify_certificate_hash(host2, 443, known_hash2, 'sha256')
    print(f"   --> Result: {'Match' if result2 else 'No Match'} (Expected: No Match)\n")

    # Test Case 3: Host with an expired certificate.
    # The connection should fail standard certificate validation before the hash is checked.
    host3 = "expired.badssl.com"
    known_hash3 = "any_hash_will_do"
    print(f"3. Testing {host3} (expired certificate)...")
    result3 = verify_certificate_hash(host3, 443, known_hash3, 'sha256')
    print(f"   --> Result: {'Match' if result3 else 'No Match'} (Expected: No Match, due to cert verification failure)\n")

    # Test Case 4: Host with a self-signed certificate.
    # The connection should fail standard certificate validation because the issuer is not trusted.
    host4 = "self-signed.badssl.com"
    known_hash4 = "another_hash"
    print(f"4. Testing {host4} (self-signed certificate)...")
    result4 = verify_certificate_hash(host4, 443, known_hash4, 'sha256')
    print(f"   --> Result: {'Match' if result4 else 'No Match'} (Expected: No Match, due to cert verification failure)\n")

    # Test Case 5: A non-existent host.
    # The connection should fail at the network level.
    host5 = "this-domain-does-not-exist-abcdef.com"
    known_hash5 = "yet_another_hash"
    print(f"5. Testing {host5} (non-existent host)...")
    result5 = verify_certificate_hash(host5, 443, known_hash5, 'sha256')
    print(f"   --> Result: {'Match' if result5 else 'No Match'} (Expected: No Match, due to network error)\n")