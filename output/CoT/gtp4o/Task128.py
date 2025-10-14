# Chain-of-Through Process:
# 1) Problem understanding: Provide functions to generate random numbers and tokens.
# 2) Security requirements: Use secrets (cryptographically secure), validate inputs.
# 3) Secure coding generation: Use secrets.randbelow for uniform distribution; avoid modulo bias.
# 4) Code review: Ensure parameter checks, no global state reliance, and safe output.
# 5) Secure code output: Final code uses secrets and input validation, with 5 test cases.

import secrets

def generate_random_numbers(count: int, min_val: int, max_val: int):
    if count < 0:
        raise ValueError("count must be non-negative")
    if min_val > max_val:
        raise ValueError("min_val must be <= max_val")
    span = (max_val - min_val) + 1
    if span <= 0:
        # handle potential overflow scenarios, though Python int is unbounded
        raise ValueError("invalid range span")
    result = []
    for _ in range(count):
        r = secrets.randbelow(span)  # uniform in [0, span-1]
        result.append(min_val + r)
    return result

def generate_secure_token(byte_length: int) -> str:
    if byte_length <= 0:
        raise ValueError("byte_length must be positive")
    # token_urlsafe uses the given number of bytes and encodes to URL-safe base64 without padding
    return secrets.token_urlsafe(byte_length)

if __name__ == "__main__":
    # 5 test cases
    try:
        # 1) 5 numbers between 1 and 10
        print("Test1 numbers [1,10]:")
        print(generate_random_numbers(5, 1, 10))

        # 2) Secure token with 16 bytes
        print("Test2 token (16 bytes):")
        print(generate_secure_token(16))

        # 3) 10 numbers between -50 and 50
        print("Test3 numbers [-50,50]:")
        print(generate_random_numbers(10, -50, 50))

        # 4) Secure token with 32 bytes
        print("Test4 token (32 bytes):")
        print(generate_secure_token(32))

        # 5) 3 numbers in [0,0]
        print("Test5 numbers [0,0]:")
        print(generate_random_numbers(3, 0, 0))
    except ValueError as e:
        print("Input error:", e)