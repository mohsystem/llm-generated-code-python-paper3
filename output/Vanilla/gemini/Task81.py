import ssl
import socket
import hashlib

def check_certificate_hash(host, port, known_hash):
    """
    Connects to a host, retrieves its SSL certificate, calculates its SHA-256 hash,
    and compares it to a known hash.
    """
    try:
        # Get certificate in PEM format from the server
        pem_cert = ssl.get_server_certificate((host, port))
        
        # Convert the PEM (text) format to DER (binary) format
        der_cert = ssl.PEM_cert_to_DER_cert(pem_cert)
        
        # Calculate the SHA-256 hash of the DER-encoded certificate
        calculated_hash = hashlib.sha256(der_cert).hexdigest()
        
        # Perform a case-insensitive comparison with the known hash
        return calculated_hash.lower() == known_hash.lower()
        
    except (ssl.SSLError, socket.gaierror, ConnectionRefusedError, socket.timeout) as e:
        print(f"  Error checking {host}: {e}")
        return False
    except Exception as e:
        print(f"  An unexpected error occurred for {host}: {e}")
        return False

def main():
    # NOTE: These hashes are time-sensitive and may need to be updated as
    # websites rotate their SSL certificates. The hashes provided are for the
    # *entire* DER-encoded certificate, not just the public key.
    # The values were correct at the time of writing.

    test_cases = [
        {
            "host": "google.com",
            "hash": "19f7a72675b331481b21cb4e488135891e4f34614207963d722108709328246a",
            "expected": True
        },
        {
            "host": "github.com",
            "hash": "346b45b239094d2b2746487e452a2656973e6f21789c6d5b035f5022e032230a",
            "expected": True
        },
        {
            "host": "example.com",
            "hash": "this_is_an_incorrect_hash_string_for_testing_failure1234567890",
            "expected": False
        },
        {
            "host": "self-signed.badssl.com",
            "hash": "987724f28012626e205a91438b417c8227b403f752496a71e16c905f884a4411",
            "expected": True
        },
        {
            "host": "thishostdoesnotexist12345.com",
            "hash": "any_hash_will_do_since_host_is_unreachable",
            "expected": False
        }
    ]

    print("--- Running Python Test Cases ---")
    for i, test in enumerate(test_cases):
        print(f"Test {i + 1}: Checking host {test['host']}")
        result = check_certificate_hash(test['host'], 443, test['hash'])
        print(f"  Result: {result}")
        print(f"  Expected: {test['expected']}")
        status = "PASS" if result == test['expected'] else "FAIL"
        print(f"  Status: {status}\n")

if __name__ == "__main__":
    main()