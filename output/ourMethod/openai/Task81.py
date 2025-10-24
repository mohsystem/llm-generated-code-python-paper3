import ssl
import socket
import secrets
import binascii
import string
from typing import Optional

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from datetime import datetime, timedelta
    HAVE_CRYPTOGRAPHY = True
except Exception:
    HAVE_CRYPTOGRAPHY = False


def _create_strict_tls_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    if hasattr(ssl, "TLSVersion"):
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    else:
        ctx.options |= getattr(ssl, "OP_NO_SSLv2", 0)
        ctx.options |= getattr(ssl, "OP_NO_SSLv3", 0)
        ctx.options |= getattr(ssl, "OP_NO_TLSv1", 0)
        ctx.options |= getattr(ssl, "OP_NO_TLSv1_1", 0)
    return ctx


def _normalize_fingerprint(expected_hash_hex: str, hash_name: str = "sha256") -> str:
    if not isinstance(expected_hash_hex, str):
        raise ValueError("expected_hash_hex must be a string")
    if hash_name.lower() != "sha256":
        raise ValueError("Only SHA-256 is supported")
    # Keep only hex digits; ignore colons/spaces
    cleaned = "".join(ch for ch in expected_hash_hex if ch in string.hexdigits)
    cleaned = cleaned.lower()
    if len(cleaned) != 64:  # 32 bytes => 64 hex chars for SHA-256
        raise ValueError("Invalid fingerprint length for SHA-256")
    return cleaned


def _sha256_hex(data: bytes) -> str:
    if HAVE_CRYPTOGRAPHY:
        h = hashes.Hash(hashes.SHA256())
        h.update(data)
        digest = h.finalize()
    else:
        # Fallback: use hashlib if cryptography unavailable
        import hashlib
        digest = hashlib.sha256(data).digest()
    return binascii.hexlify(digest).decode("ascii")


def _pem_to_der(pem_data: str) -> bytes:
    """
    Convert PEM certificate to DER bytes using cryptography if available, else manual base64 decode.
    """
    if not isinstance(pem_data, str):
        raise ValueError("PEM data must be a string")
    if HAVE_CRYPTOGRAPHY:
        cert = x509.load_pem_x509_certificate(pem_data.encode("utf-8"))
        return cert.public_bytes(serialization.Encoding.DER)
    # Manual decode without full validation
    lines = pem_data.strip().splitlines()
    begin = "-----BEGIN CERTIFICATE-----"
    end = "-----END CERTIFICATE-----"
    in_body = False
    b64_lines = []
    for line in lines:
        line = line.strip()
        if line == begin:
            in_body = True
            continue
        if line == end:
            break
        if in_body:
            b64_lines.append(line)
    if not b64_lines:
        raise ValueError("Invalid PEM certificate")
    import base64
    try:
        return base64.b64decode("".join(b64_lines), validate=True)
    except Exception as exc:
        raise ValueError("Invalid base64 in PEM certificate") from exc


def compute_certificate_fingerprint_from_pem(cert_pem: str, hash_name: str = "sha256") -> str:
    """
    Compute the SHA-256 fingerprint (hex, lowercase) of a certificate given in PEM format.
    """
    if hash_name.lower() != "sha256":
        raise ValueError("Only SHA-256 is supported")
    der = _pem_to_der(cert_pem)
    return _sha256_hex(der)


def certificate_matches_hash(cert_pem: str, expected_hash_hex: str, hash_name: str = "sha256") -> bool:
    """
    Return True if the given certificate PEM's SHA-256 fingerprint matches the expected hash.
    Normalizes expected hash by removing separators and case. Uses constant-time comparison.
    """
    try:
        expected = _normalize_fingerprint(expected_hash_hex, hash_name=hash_name)
        actual = compute_certificate_fingerprint_from_pem(cert_pem, hash_name=hash_name)
        return secrets.compare_digest(actual, expected)
    except Exception:
        return False


def fetch_server_leaf_cert_der(hostname: str, port: int = 443, timeout: float = 5.0) -> bytes:
    """
    Establishes a TLS connection with strict verification and returns the leaf certificate in DER.
    """
    if not isinstance(hostname, str) or not hostname or len(hostname) > 253:
        raise ValueError("Invalid hostname")
    if not isinstance(port, int) or not (1 <= port <= 65535):
        raise ValueError("Invalid port")
    if not isinstance(timeout, (int, float)) or timeout <= 0 or timeout > 120:
        raise ValueError("Invalid timeout")
    ctx = _create_strict_tls_context()
    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            der = ssock.getpeercert(binary_form=True)
            if not der:
                raise RuntimeError("Failed to retrieve peer certificate")
            return der


def server_certificate_matches_hash(
    hostname: str,
    expected_hash_hex: str,
    port: int = 443,
    timeout: float = 5.0,
    hash_name: str = "sha256",
) -> bool:
    """
    Fetch the server's leaf certificate (with strict TLS verification) and compare its fingerprint
    to the expected value. Returns False on any failure.
    """
    try:
        expected = _normalize_fingerprint(expected_hash_hex, hash_name=hash_name)
        der = fetch_server_leaf_cert_der(hostname, port=port, timeout=timeout)
        actual = _sha256_hex(der)
        return secrets.compare_digest(actual, expected)
    except Exception:
        return False


def _generate_self_signed_cert_pem(common_name: str = "localhost") -> str:
    """
    Generate a self-signed RSA 2048-bit certificate in PEM format for testing.
    Requires cryptography. Raises if cryptography is unavailable.
    """
    if not HAVE_CRYPTOGRAPHY:
        raise RuntimeError("cryptography package is required to generate a self-signed certificate")
    if not isinstance(common_name, str) or not common_name:
        raise ValueError("Invalid common name")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Co"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )
    now = datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key=key, algorithm=hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    return pem


def _format_colon_separated(hex_str: str) -> str:
    """
    Turn a contiguous hex string into colon-separated uppercase pairs (common fingerprint format).
    """
    pairs = [hex_str[i : i + 2] for i in range(0, len(hex_str), 2)]
    return ":".join(pairs).upper()


def main() -> None:
    # Test 1: Self-signed certificate matches its own SHA-256 fingerprint
    try:
        pem = _generate_self_signed_cert_pem("test.local") if HAVE_CRYPTOGRAPHY else None
        if pem:
            fp = compute_certificate_fingerprint_from_pem(pem)
            res1 = certificate_matches_hash(pem, fp)
        else:
            # Fallback: simulate using a small generated PEM-like block (not a real cert)
            # Since generating a cert requires cryptography, fallback test ensures function returns False safely.
            dummy_pem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"
            fp = "0" * 64
            res1 = certificate_matches_hash(dummy_pem, fp)
        print(f"Test1_match_self_signed: {res1}")
    except Exception as e:
        print(f"Test1_match_self_signed: False  # error: {str(e)[:60]}")

    # Test 2: Mismatch with wrong fingerprint
    try:
        if HAVE_CRYPTOGRAPHY:
            wrong_fp = "00" * 32
            res2 = certificate_matches_hash(pem, wrong_fp)
        else:
            res2 = False  # expected since fallback isn't a real cert
        print(f"Test2_mismatch_wrong_hash: {res2}")
    except Exception as e:
        print(f"Test2_mismatch_wrong_hash: False  # error: {str(e)[:60]}")

    # Test 3: Colon-separated uppercase fingerprint should still match after normalization
    try:
        if HAVE_CRYPTOGRAPHY:
            colon_fp = _format_colon_separated(fp)
            res3 = certificate_matches_hash(pem, colon_fp)
        else:
            res3 = False
        print(f"Test3_match_colon_uppercase: {res3}")
    except Exception as e:
        print(f"Test3_match_colon_uppercase: False  # error: {str(e)[:60]}")

    # Test 4: Invalid PEM should fail closed (return False)
    try:
        invalid_pem = "INVALID DATA"
        res4 = certificate_matches_hash(invalid_pem, "AA" * 32)
        print(f"Test4_invalid_pem_fail_closed: {res4}")
    except Exception as e:
        print(f"Test4_invalid_pem_fail_closed: False  # error: {str(e)[:60]}")

    # Test 5: Live server certificate check (example.com). If network/TLS unavailable, should not crash.
    try:
        host = "example.com"
        # First fetch to get the actual fingerprint (strict TLS)
        der = fetch_server_leaf_cert_der(host)
        live_fp = _sha256_hex(der)
        res5 = server_certificate_matches_hash(host, live_fp)
        print(f"Test5_live_server_match: {res5}")
    except Exception as e:
        print(f"Test5_live_server_match: False  # skipped/error: {str(e)[:60]}")


if __name__ == "__main__":
    main()