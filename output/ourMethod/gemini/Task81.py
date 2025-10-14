import socket
import ssl
import hashlib
import hmac
from typing import Optional

def check_certificate_hash(host: str, port: int, known_hash: str, algorithm: str) -> bool:
    """
    Checks if the SSL certificate of a remote host matches a known hash.

    Args:
        host: The hostname to connect to.
        port: The port to connect to.
        known_hash: The known certificate hash as a hex string.
        algorithm: The hashing algorithm (e.g., "sha256").

    Returns:
        True if the certificate hash matches, False otherwise.
    """
    if not host or not known_hash or not algorithm:
        return False

    try:
        context = ssl.create_default_context()
        # The connection will be closed by the with statement
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert_der: Optional[bytes] = ssock.getpeercert(binary_form=True)
                if not cert_der:
                    print(f"Error: Could not retrieve certificate from {host}")
                    return False
                
                h = hashlib.new(algorithm)
                h.update(cert_der)
                calculated_hash = h.hexdigest()

                # Use hmac.compare_digest for constant-time comparison to prevent timing attacks
                return hmac.compare_digest(calculated_hash, known_hash.lower())

    except (socket.gaierror, ConnectionRefusedError):
        print(f"Error: Could not resolve or connect to host: {host}")
    except ssl.SSLCertVerificationError as e:
        print(f"Error: Certificate verification failed for {host}: {e}")
    except (ssl.SSLError, socket.timeout, OSError) as e:
        print(f"Error: SSL/Socket error connecting to {host}: {e}")
    except ValueError:
        print(f"Error: Unsupported hash algorithm: {algorithm}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        
    return False

def main():
    """Runs test cases for the certificate hash checker."""
    # NOTE: These hashes are time-sensitive and will change when certificates are renewed.
    # You may need to update them for the tests to pass.
    GOOGLE_SHA256 = "1a3b865582e022f42a6c8e317c223c3b0693a61f2382855140b28e57973c150c"
    GITHUB_SHA256 = "1980318288b3986a420f4c0842271676f45237c95a25e6215b22b069d2c55b9e"
    FAKE_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

    print("Running test cases...")

    # Test Case 1: Positive match for google.com
    test1 = check_certificate_hash("www.google.com", 443, GOOGLE_SHA256, "sha256")
    print(f"1. www.google.com with correct hash: {'PASS' if test1 else 'FAIL'}")

    # Test Case 2: Negative match (wrong hash) for google.com
    test2 = check_certificate_hash("www.google.com", 443, FAKE_HASH, "sha256")
    print(f"2. www.google.com with incorrect hash: {'PASS' if not test2 else 'FAIL'}")

    # Test Case 3: Negative match (wrong host for the hash)
    test3 = check_certificate_hash("www.github.com", 443, GOOGLE_SHA256, "sha256")
    print(f"3. www.github.com with google.com hash: {'PASS' if not test3 else 'FAIL'}")

    # Test Case 4: Connection error (invalid host)
    test4 = check_certificate_hash("invalid.hostname.that.does.not.exist", 443, FAKE_HASH, "sha256")
    print(f"4. Invalid hostname: {'PASS' if not test4 else 'FAIL'}")

    # Test Case 5: Positive match for github.com
    test5 = check_certificate_hash("www.github.com", 443, GITHUB_SHA256, "sha256")
    print(f"5. www.github.com with correct hash: {'PASS' if test5 else 'FAIL'}")


if __name__ == "__main__":
    main()