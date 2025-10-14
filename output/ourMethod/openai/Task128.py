import secrets
import base64
from typing import List


MAX_BYTES = 1_048_576  # 1 MiB safety cap
ALPHANUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


def random_bytes(length: int) -> bytes:
    if not isinstance(length, int) or length < 0 or length > MAX_BYTES:
        raise ValueError("length out of allowed range")
    return secrets.token_bytes(length)


def to_hex(data: bytes) -> str:
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("data must be bytes-like")
    return data.hex()


def random_hex(n_bytes: int) -> str:
    return to_hex(random_bytes(n_bytes))


def random_base64url(n_bytes: int) -> str:
    # URL-safe Base64 without padding
    return base64.urlsafe_b64encode(random_bytes(n_bytes)).rstrip(b"=").decode("ascii")


def random_alphanum(length: int) -> str:
    if not isinstance(length, int) or length < 0 or length > MAX_BYTES:
        raise ValueError("length out of allowed range")
    return "".join(secrets.choice(ALPHANUM) for _ in range(length))


def random_int(min_val: int, max_val: int) -> int:
    if not isinstance(min_val, int) or not isinstance(max_val, int):
        raise ValueError("inputs must be integers")
    if min_val > max_val:
        raise ValueError("min_val must be <= max_val")
    # Python big ints handle full range safely
    return min_val + secrets.randbelow((max_val - min_val) + 1)


def main() -> None:
    # 5 test cases
    print("Random hex (16 bytes):", random_hex(16))
    print("Random base64url (24 bytes):", random_base64url(24))
    print("Random alphanum (20 chars):", random_alphanum(20))
    print("Random int [0,10]:", random_int(0, 10))
    print("Random int full 32-bit range example:", random_int(-(2**31), 2**31 - 1))


if __name__ == "__main__":
    main()