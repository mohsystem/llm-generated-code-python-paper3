
import hashlib
import base64
import re

def check_certificate_hash(certificate_pem, known_hash, algorithm='sha256'):
    try:
        # Remove PEM headers and whitespace
        cert_content = certificate_pem.replace('-----BEGIN CERTIFICATE-----', '')
        cert_content = cert_content.replace('-----END CERTIFICATE-----', '')
        cert_content = re.sub(r'\\s+', '', cert_content)
        
        # Decode base64
        cert_bytes = base64.b64decode(cert_content)
        
        # Calculate hash based on algorithm
        if algorithm.lower() == 'sha256' or algorithm.lower() == 'sha-256':
            hash_obj = hashlib.sha256(cert_bytes)
        elif algorithm.lower() == 'sha1' or algorithm.lower() == 'sha-1':
            hash_obj = hashlib.sha1(cert_bytes)
        elif algorithm.lower() == 'md5':
            hash_obj = hashlib.md5(cert_bytes)
        else:
            return False
        
        # Get hex digest
        calculated_hash = hash_obj.hexdigest()
        
        # Normalize known hash (remove colons and spaces)
        known_hash_normalized = known_hash.replace(':', '').replace(' ', '').lower()
        
        # Compare hashes
        return calculated_hash == known_hash_normalized
        
    except Exception as e:
        return False


if __name__ == '__main__':
    # Test certificate (self-signed example)
    test_cert = """-----BEGIN CERTIFICATE-----\nMIICWzCCAcSgAwIBAgIJAL7xG3YqkqWGMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV\nBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX\naWRnaXRzIFB0eSBMdGQwHhcNMjEwMTAxMDAwMDAwWhcNMjIwMTAxMDAwMDAwWjBF\nMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50\nZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB\ngQDHc0BcF8y6tN3jKBvXvL7VdqOYWlYwXMdGpLvXgNF5h6m6R7X9J4qH8o4F3k9Q\ny6z8K7dF9e3pQ6mL4x2X7fG5j8K9L3m4x5N6p7qQ8R3j4K9L2m5x6N7q8R3j5K9L\n3m5x7N8q9R4j6K0L4m6x8N0q0R5j7K1L5m7x9N1q1R6j8K2L6m8xQIDAQABo1Aw\nTjAdBgNVHQ4EFgQU8h3j9K0L4m6x8N0q0R5j7K1L5m8wHwYDVR0jBBgwFoAU8h3j\n9K0L4m6x8N0q0R5j7K1L5m8wDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOB\ngQBZ3j9K1L5m7x9N1q1R6j8K2L6m8x0N2q2R7j9K3L7m9xN3q3R8jK4L8mxN4q4R\n9jK5L9mx0N5q5R0jK6LmxN6q6R1jK7LmxN7q7R2jK8LmxN8q8R3jK9Lmx\n-----END CERTIFICATE-----"""
    
    # Test case 1: Valid SHA-256 hash
    print("Test 1 - Valid SHA-256:", 
          check_certificate_hash(test_cert, "a1b2c3d4e5f6", "sha256"))
    
    # Test case 2: Invalid hash
    print("Test 2 - Invalid hash:", 
          check_certificate_hash(test_cert, "0000000000000000", "sha256"))
    
    # Test case 3: SHA-1 algorithm
    print("Test 3 - SHA-1:", 
          check_certificate_hash(test_cert, "abcdef123456", "sha1"))
    
    # Test case 4: MD5 algorithm
    print("Test 4 - MD5:", 
          check_certificate_hash(test_cert, "fedcba654321", "md5"))
    
    # Test case 5: Invalid certificate
    print("Test 5 - Invalid cert:", 
          check_certificate_hash("-----BEGIN CERTIFICATE-----\\nINVALID\\n-----END CERTIFICATE-----",
                                 "a1b2c3d4e5f6", "sha256"))
