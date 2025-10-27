# Chain-of-Through Step 1: Problem understanding
# - Generate two random ints in [10, 1000], compute difference, print results.
# - Provide a function that accepts parameters and returns outputs.
# Chain-of-Through Step 2: Security requirements
# - Use secrets for cryptographically secure randomness.
# Chain-of-Through Step 3: Secure coding generation
# - Validate bounds and use inclusive uniform selection.
# Chain-of-Through Step 4: Code review
# - Ensure span computed safely and absolute difference.
# Chain-of-Through Step 5: Secure code output

import secrets

def generate_and_diff(min_v: int, max_v: int):
    if min_v > max_v:
        raise ValueError("min_v must be <= max_v")
    span = (max_v - min_v) + 1
    a = min_v + secrets.randbelow(span)
    b = min_v + secrets.randbelow(span)
    diff = abs(a - b)
    return (a, b, diff)

if __name__ == "__main__":
    # 5 test cases
    for i in range(1, 6):
        a, b, d = generate_and_diff(10, 1000)
        print(f"Test {i}: First={a}, Second={b}, Difference={d}")