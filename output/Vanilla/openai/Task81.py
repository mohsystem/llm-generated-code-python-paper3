import hashlib

def matches_known_hash(cert_bytes: bytes, known_hash_hex: str, algorithm: str = "sha256") -> bool:
    try:
        hasher = hashlib.new(algorithm.lower())
        hasher.update(cert_bytes)
        digest_hex = hasher.hexdigest()
        return digest_hex.lower() == known_hash_hex.lower()
    except Exception:
        return False

if __name__ == "__main__":
    algo = "sha256"

    cert1 = b"abc"
    hash1 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    print(matches_known_hash(cert1, hash1, algo))  # true

    cert2 = b""
    hash2 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    print(matches_known_hash(cert2, hash2, algo))  # true

    cert3 = b"hello"
    hash3 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    print(matches_known_hash(cert3, hash3, algo))  # true

    cert4 = b"test"
    wrong_hash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    print(matches_known_hash(cert4, wrong_hash, algo))  # false

    cert5 = bytes([0x00, 0x01, 0x02, 0x03])
    print(matches_known_hash(cert5, hash1, algo))  # false