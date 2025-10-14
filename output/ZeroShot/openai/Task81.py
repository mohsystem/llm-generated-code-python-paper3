import base64
import hashlib
import hmac
import re

def certificate_matches_hash(cert_data, expected_sha256_hex):
    if cert_data is None or expected_sha256_hex is None:
        return False
    expected = _hex_to_bytes(_sanitize_hex(expected_sha256_hex))
    if expected is None or len(expected) != 32:
        return False

    try:
        if isinstance(cert_data, (bytes, bytearray)):
            data = bytes(cert_data)
        elif isinstance(cert_data, str):
            if "-----BEGIN CERTIFICATE-----" in cert_data:
                data = _pem_to_der(cert_data)
                if data is None:
                    return False
            else:
                data = cert_data.encode("utf-8")
        else:
            return False
    except Exception:
        return False

    actual = hashlib.sha256(data).digest()
    return hmac.compare_digest(actual, expected)

def _sanitize_hex(s: str) -> str:
    return re.sub(r'[^0-9A-Fa-f]', '', s)

def _hex_to_bytes(h: str):
    try:
        if len(h) % 2 != 0:
            return None
        return bytes.fromhex(h)
    except ValueError:
        return None

def _pem_to_der(pem: str):
    header = "-----BEGIN CERTIFICATE-----"
    footer = "-----END CERTIFICATE-----"
    start = pem.find(header)
    end = pem.find(footer)
    if start < 0 or end < 0 or end <= start:
        return None
    b64 = pem[start+len(header):end]
    # Remove whitespace
    b64 = re.sub(r'\s+', '', b64)
    try:
        return base64.b64decode(b64, validate=True)
    except Exception:
        return None

if __name__ == "__main__":
    hello = b"hello"
    sha_hello = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    wrong = "00" * 32

    pem_hello = """-----BEGIN CERTIFICATE-----
aGVsbG8=
-----END CERTIFICATE-----"""

    pem_hello_messy = """-----BEGIN CERTIFICATE-----
  aG Vs
  bG8=
-----END CERTIFICATE-----"""

    invalid_pem = """-----BEGIN CERTIFICATE-----
???not_base64@@@
-----END CERTIFICATE-----"""

    print("Test1 (DER correct):", certificate_matches_hash(hello, sha_hello))
    print("Test2 (DER wrong):  ", certificate_matches_hash(hello, wrong))
    print("Test3 (PEM correct):", certificate_matches_hash(pem_hello, sha_hello))
    print("Test4 (PEM messy):  ", certificate_matches_hash(pem_hello_messy, sha_hello))
    print("Test5 (PEM invalid):", certificate_matches_hash(invalid_pem, sha_hello))