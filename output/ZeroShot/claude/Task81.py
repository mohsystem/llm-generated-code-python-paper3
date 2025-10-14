
import hashlib
import base64
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def check_certificate_hash(certificate_pem, known_hash, algorithm='sha256'):
    try:
        # Remove PEM headers and whitespace
        cert_content = certificate_pem.replace('-----BEGIN CERTIFICATE-----', '')
        cert_content = cert_content.replace('-----END CERTIFICATE-----', '')
        cert_content = cert_content.replace('\\n', '').replace('\\r', '').replace(' ', '')
        
        # Decode Base64
        cert_bytes = base64.b64decode(cert_content)
        
        # Load certificate
        cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
        
        # Calculate hash
        if algorithm.lower() in ['sha256', 'sha-256']:
            hash_obj = hashlib.sha256()
        elif algorithm.lower() in ['sha1', 'sha-1']:
            hash_obj = hashlib.sha1()
        elif algorithm.lower() == 'md5':
            hash_obj = hashlib.md5()
        else:
            return False
        
        hash_obj.update(cert.public_bytes(encoding=x509.Encoding.DER))
        cert_hash = hash_obj.hexdigest()
        
        # Normalize known hash (remove colons and spaces)
        normalized_known_hash = known_hash.replace(':', '').replace(' ', '').lower()
        
        # Compare hashes
        return cert_hash.lower() == normalized_known_hash
    except Exception as e:
        return False

if __name__ == '__main__':
    # Test certificate
    test_cert = """-----BEGIN CERTIFICATE-----\nMIICLDCCAdKgAwIBAgIBADAKBggqhkjOPQQDAjB9MQswCQYDVQQGEwJ1czELMAkG\nA1UECAwCQ0ExCzAJBgNVBAcMAlNGMQ8wDQYDVQQKDAZKb3lFbnQxEDAOBgNVBAsM\nB05vZGUtY2ExFDASBgNVBAMMC2V4YW1wbGUuY29tMRswGQYJKoZIhvcNAQkBFgxh\nQGV4YW1wbGUuY29tMB4XDTIxMDEwMTAwMDAwMFoXDTMxMDEwMTAwMDAwMFowfTEL\nMAkGA1UEBhMCdXMxCzAJBgNVBAgMAkNBMQswCQYDVQQHDAJTRjEPMA0GA1UECgwG\nSm95RW50MRAwDgYDVQQLDAdOb2RlLWNhMRQwEgYDVQQDDAtleGFtcGxlLmNvbTEb\nMBkGCSqGSIb3DQEJARYMYUBleGFtcGxlLmNvbTBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABEg7eqR4yMGb2N8rTOi3OKrPtGLLzqVPnzqLjLwrPmLqLnVChdPMbZHL\nLyZuMN0wPgwGNxQqPVLfvAp9fkqFfqajUDBOMB0GA1UdDgQWBBQ7WxJ8rYxNQvJm\nlzWVhFWrfVWnlDAfBgNVHSMEGDAWgBQ7WxJ8rYxNQvJmlzWVhFWrfVWnlDAMBgNV\nHRMEBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQDLWlPGzNCPKqBvbLDPuLOdRVjJ\nkIrGqTI6+xB3L2x8hAIgCHMzH8KwHgfTLxP9gFmqFYhpUkGJvVYMqfnCMZJmLrk=\n-----END CERTIFICATE-----"""
    
    # Test Case 1: Valid SHA-256 hash
    hash1 = "8f43288ad272f3103b6fb1428485ea3014c0bcf547a2f1d4e8e1e2c6e5f7d8c9"
    print(f"Test 1 - Valid SHA-256: {check_certificate_hash(test_cert, hash1, 'sha256')}")
    
    # Test Case 2: Valid SHA-1 hash
    hash2 = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
    print(f"Test 2 - Valid SHA-1: {check_certificate_hash(test_cert, hash2, 'sha1')}")
    
    # Test Case 3: Invalid hash
    hash3 = "0000000000000000000000000000000000000000000000000000000000000000"
    print(f"Test 3 - Invalid hash: {check_certificate_hash(test_cert, hash3, 'sha256')}")
    
    # Test Case 4: Hash with colons
    hash4 = "8f:43:28:8a:d2:72:f3:10:3b:6f:b1:42:84:85:ea:30:14:c0:bc:f5:47:a2:f1:d4:e8:e1:e2:c6:e5:f7:d8:c9"
    print(f"Test 4 - Hash with colons: {check_certificate_hash(test_cert, hash4, 'sha256')}")
    
    # Test Case 5: Invalid certificate
    print(f"Test 5 - Invalid cert: {check_certificate_hash('invalid', hash1, 'sha256')}")
