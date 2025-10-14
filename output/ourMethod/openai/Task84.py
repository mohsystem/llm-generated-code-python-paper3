from typing import Final
import base64
import secrets

MIN_BYTES: Final[int] = 16
MAX_BYTES: Final[int] = 64

def generate_session_id(num_bytes: int) -> str:
    if not isinstance(num_bytes, int):
        raise TypeError("num_bytes must be an int")
    if num_bytes < MIN_BYTES or num_bytes > MAX_BYTES:
        raise ValueError(f"num_bytes must be between {MIN_BYTES} and {MAX_BYTES}")
    token_bytes = secrets.token_bytes(num_bytes)
    # URL-safe Base64 without padding
    return base64.urlsafe_b64encode(token_bytes).rstrip(b"=").decode("ascii")

if __name__ == "__main__":
    tests = [16, 24, 32, 48, 64]
    for t in tests:
        try:
            print(generate_session_id(t))
        except Exception as e:
            print(f"Error: {e}")