import base64
import binascii
import hashlib
import hmac

class Task81:
    @staticmethod
    def _normalize_alg(alg: str) -> str:
        if alg is None:
            raise ValueError("Algorithm cannot be null.")
        up = alg.strip().upper()
        if up in ("SHA-256", "SHA256"):
            return "sha256"
        if up in ("SHA-384", "SHA384"):
            return "sha384"
        if up in ("SHA-512", "SHA512"):
            return "sha512"
        raise ValueError("Unsupported algorithm. Allowed: SHA-256, SHA-384, SHA-512")

    @staticmethod
    def _hex_to_bytes(h: str) -> bytes:
        if h is None:
            raise ValueError("Expected hex cannot be null.")
        # Keep only hex digits
        cleaned = ''.join(ch for ch in h if ch.lower() in '0123456789abcdef')
        if len(cleaned) == 0 or len(cleaned) % 2 != 0:
            raise ValueError("Invalid hex fingerprint format.")
        try:
            return binascii.unhexlify(cleaned)
        except binascii.Error as e:
            raise ValueError("Invalid hex digit in fingerprint.") from e

    @staticmethod
    def _bytes_to_hex(b: bytes) -> str:
        return binascii.hexlify(b).decode('ascii').upper()

    @staticmethod
    def _pem_to_der_if_pem(s: str):
        if s is None:
            return None
        marker_begin = "-----BEGIN CERTIFICATE-----"
        marker_end = "-----END CERTIFICATE-----"
        start = s.find(marker_begin)
        end = s.find(marker_end)
        if start == -1 or end == -1 or end < start:
            return None
        base64_content = s[start + len(marker_begin):end]
        try:
            # Decode with base64 that ignores whitespace
            der = base64.b64decode(base64_content.encode('ascii'), validate=False)
            return der
        except Exception as e:
            raise ValueError("Invalid PEM base64 content.") from e

    @staticmethod
    def _compute_digest(der: bytes, alg: str) -> bytes:
        hname = Task81._normalize_alg(alg)
        h = hashlib.new(hname)
        h.update(der)
        return h.digest()

    @staticmethod
    def compute_cert_digest_hex(der: bytes, alg: str) -> str:
        if der is None:
            raise ValueError("Certificate data cannot be null.")
        return Task81._bytes_to_hex(Task81._compute_digest(der, alg))

    @staticmethod
    def certificate_matches_hash(cert_bytes: bytes, expected_hex: str, alg: str) -> bool:
        if cert_bytes is None:
            raise ValueError("Certificate data cannot be null.")
        expected = Task81._hex_to_bytes(expected_hex)
        actual = Task81._compute_digest(cert_bytes, alg)
        return hmac.compare_digest(actual, expected)

    @staticmethod
    def certificate_matches_hash_from_pem(pem: str, expected_hex: str, alg: str) -> bool:
        der = Task81._pem_to_der_if_pem(pem)
        if der is None:
            raise ValueError("Invalid PEM format or certificate block not found.")
        return Task81.certificate_matches_hash(der, expected_hex, alg)

def _colonize_hex(h: str) -> str:
    cleaned = ''.join(ch for ch in h.upper() if ch in '0123456789ABCDEF')
    return ':'.join(cleaned[i:i+2] for i in range(0, len(cleaned), 2))

def _b64encode(data: bytes, line_width: int = 64) -> str:
    b = base64.b64encode(data).decode('ascii')
    if line_width and line_width > 0:
        return '\n'.join(b[i:i+line_width] for i in range(0, len(b), line_width))
    return b

if __name__ == "__main__":
    # Test 1: DER match
    cert1 = b"DERCERT-ONE"
    expected1 = Task81.compute_cert_digest_hex(cert1, "SHA-256")
    print("Test1 (DER match, SHA-256):", Task81.certificate_matches_hash(cert1, expected1, "SHA-256"))

    # Test 2: DER mismatch
    cert2 = b"ANOTHER-CERT"
    wrong_expected = "00" * 32
    print("Test2 (DER mismatch):", Task81.certificate_matches_hash(cert2, wrong_expected, "SHA-256"))

    # Test 3: PEM match
    der3 = bytes([1, 2, 3, 4, 5])
    pem_body = _b64encode(der3, 64)
    pem = "-----BEGIN CERTIFICATE-----\n" + pem_body + "\n-----END CERTIFICATE-----\n"
    expected3 = Task81.compute_cert_digest_hex(der3, "SHA-256")
    print("Test3 (PEM match, SHA-256):", Task81.certificate_matches_hash_from_pem(pem, expected3, "SHA-256"))

    # Test 4: Invalid algorithm handling
    try:
        Task81.certificate_matches_hash(cert1, expected1, "MD5")
        print("Test4 (Invalid alg): False")
    except ValueError:
        print("Test4 (Invalid alg): True")

    # Test 5: Colon-separated fingerprint accepted
    colon_expected1 = _colonize_hex(expected1)
    print("Test5 (Colon-separated fingerprint):", Task81.certificate_matches_hash(cert1, colon_expected1, "SHA-256"))