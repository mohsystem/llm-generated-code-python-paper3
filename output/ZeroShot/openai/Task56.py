import base64
import secrets

def generate_token(num_bytes: int) -> str:
    """
    Generates a URL-safe base64 token with cryptographically secure randomness.
    Ensures at least 32 bytes of entropy.
    """
    n = max(int(num_bytes), 32)
    token_bytes = secrets.token_bytes(n)
    return base64.urlsafe_b64encode(token_bytes).rstrip(b'=').decode('ascii')

if __name__ == "__main__":
    test_sizes = [32, 48, 64, 16, 0]
    for i, sz in enumerate(test_sizes, 1):
        tok = generate_token(sz)
        print(f"Python Token {i} ({max(sz,32)} bytes): {tok}")