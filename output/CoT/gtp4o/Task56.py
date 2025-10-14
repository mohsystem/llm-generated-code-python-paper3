# Chain-of-Through process in code generation:
# 1) Problem understanding: Generate cryptographically strong, URL-safe tokens for authentication.
# 2) Security requirements: Use secrets for CSPRNG, adequate entropy (>=128 bits), URL-safe encoding without padding.
# 3) Secure coding generation: Validate inputs, use secrets.token_bytes, base64 urlsafe encoding, strip padding.
# 4) Code review: Verified no use of weak RNG, predictable seeds, or insecure encodings.
# 5) Secure code output: Final implementation returns high-entropy, URL-safe tokens.

import base64
import secrets

def generate_auth_token(num_bytes: int) -> str:
    if not isinstance(num_bytes, int):
        raise TypeError("num_bytes must be int")
    if num_bytes < 16 or num_bytes > 64:
        raise ValueError("num_bytes must be between 16 and 64")
    raw = secrets.token_bytes(num_bytes)
    token = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    return token

if __name__ == "__main__":
    tests = [16, 24, 32, 48, 64]
    for n in tests:
        t = generate_auth_token(n)
        print(f"Bytes={n} Token={t} Length={len(t)}")