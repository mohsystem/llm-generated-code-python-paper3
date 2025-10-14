import base64
import hashlib
import hmac
from typing import Optional


def fingerprint_hex(cert_input: bytes, algorithm: str = "sha256") -> str:
    if not cert_input:
        raise ValueError("Empty certificate input")
    alg = (algorithm or "sha256").lower()
    if alg != "sha256":
        raise ValueError("Only sha256 is supported")
    der = _decode_pem_if_needed(cert_input)
    digest = hashlib.sha256(der).hexdigest()
    return digest


def matches_known_hash(cert_input: bytes, known_hash: str, algorithm: str = "sha256") -> bool:
    if cert_input is None or known_hash is None:
        return False
    alg = (algorithm or "sha256").lower()
    if alg != "sha256":
        return False
    der = _decode_pem_if_needed(cert_input)
    actual = hashlib.sha256(der).digest()
    expected = _parse_hex_flexible(known_hash)
    if expected is None or len(expected) == 0:
        return False
    if len(expected) != len(actual):
        return False
    return hmac.compare_digest(actual, expected)


def _decode_pem_if_needed(data: bytes) -> bytes:
    try:
        s = data.decode("utf-8", errors="ignore")
    except Exception:
        return data
    begin = "-----BEGIN CERTIFICATE-----"
    end = "-----END CERTIFICATE-----"
    if begin in s and end in s:
        start = s.find(begin) + len(begin)
        stop = s.find(end, start)
        if stop <= start:
            raise ValueError("Invalid PEM format")
        b64 = "".join(s[start:stop].split())
        try:
            return base64.b64decode(b64, validate=True)
        except Exception as e:
            raise ValueError("Invalid Base64 in PEM") from e
    return data


def _parse_hex_flexible(s: str) -> Optional[bytes]:
    if s is None:
        return None
    acc = []
    hex_chars = "0123456789abcdefABCDEF"
    separators = set(": -\t\r\n")
    for ch in s.strip():
        if ch in hex_chars:
            acc.append(ch)
        elif ch in separators:
            continue
        else:
            return None
    if len(acc) == 0 or (len(acc) % 2) != 0:
        return None
    hex_str = "".join(acc)
    try:
        return bytes.fromhex(hex_str)
    except ValueError:
        return None


def _to_colon_upper(hex_lower: str) -> str:
    h = hex_lower.upper()
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))


def main() -> None:
    cert1 = b"DER-CERT-ONE-123"
    cert2 = b"DER-CERT-TWO-456"
    cert3 = b"DIFFERENT-CERT-XYZ"

    fp1 = fingerprint_hex(cert1, "sha256")
    fp2 = fingerprint_hex(cert2, "sha256")
    fp3 = fingerprint_hex(cert3, "sha256")

    pem2 = (
        "-----BEGIN CERTIFICATE-----\n"
        + "\n".join([base64.encodebytes(cert2).decode("ascii").strip()])
        + "\n-----END CERTIFICATE-----\n"
    ).encode("utf-8")

    t1 = matches_known_hash(cert1, fp1, "sha256")
    t2 = matches_known_hash(cert1, _to_colon_upper(fp1), "sha256")
    t3 = matches_known_hash(cert1, fp2, "sha256")
    t4 = matches_known_hash(pem2, fp2, "sha256")
    t5 = matches_known_hash(cert3, "ZZ:11:GG", "sha256")

    print(f"Test1: {t1}")
    print(f"Test2: {t2}")
    print(f"Test3: {t3}")
    print(f"Test4: {t4}")
    print(f"Test5: {t5}")


if __name__ == "__main__":
    main()