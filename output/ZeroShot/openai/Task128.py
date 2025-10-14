import secrets

class Task128:
    @staticmethod
    def secure_random_bytes(length: int) -> bytes:
        if length < 0:
            raise ValueError("length must be non-negative")
        return secrets.token_bytes(length)

    @staticmethod
    def secure_hex_token(num_bytes: int) -> str:
        if num_bytes < 0:
            raise ValueError("num_bytes must be non-negative")
        return secrets.token_hex(num_bytes)

    @staticmethod
    def secure_random_int(min_inclusive: int, max_inclusive: int) -> int:
        if min_inclusive > max_inclusive:
            raise ValueError("min > max")
        # Python big ints handle large ranges; rejection handled internally.
        span = max_inclusive - min_inclusive + 1
        return min_inclusive + secrets.randbelow(span)

if __name__ == "__main__":
    # 5 test cases
    print("Hex token (16 bytes):", Task128.secure_hex_token(16))
    print("Random int [1, 100]:", Task128.secure_random_int(1, 100))
    print("Hex token (32 bytes):", Task128.secure_hex_token(32))
    print("Hex token (0 bytes):", Task128.secure_hex_token(0))
    print("Random int [0, 2^48]:", Task128.secure_random_int(0, 1 << 48))