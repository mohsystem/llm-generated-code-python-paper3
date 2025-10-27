import secrets
import sys

# A standard double-precision float has 53 bits of significand precision.
# We generate a 64-bit integer to ensure sufficient randomness and scale it.
RANDOM_BITS = 64
MAX_RANDOM_INT = (1 << RANDOM_BITS)

def generate_random_float_strings():
    """
    Generates three cryptographically secure random floats and returns them as strings.
    This uses the 'secrets' module, which is suitable for cryptographic use.
    
    Returns:
        A list of three strings, each representing a random float in [0.0, 1.0).
    """
    result = []
    for _ in range(3):
        # Generate a secure random integer and scale it to a float in [0.0, 1.0)
        random_int = secrets.randbits(RANDOM_BITS)
        random_float = random_int / MAX_RANDOM_INT
        result.append(str(random_float))
    return result

if __name__ == "__main__":
    print("Running 5 test cases...")
    for i in range(5):
        print(f"Test Case {i + 1}:")
        try:
            random_strings = generate_random_float_strings()
            if len(random_strings) == 3:
                print(f"  String 1: {random_strings[0]}")
                print(f"  String 2: {random_strings[1]}")
                print(f"  String 3: {random_strings[2]}")
            else:
                print("  Error: Did not generate 3 strings.", file=sys.stderr)
        except Exception as e:
            print(f"  An error occurred: {e}", file=sys.stderr)
        print()