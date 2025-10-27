import random
from typing import List

def generate_random_float_strings() -> List[str]:
    """
    Generates three random floats and converts them to strings.
    
    The 'random' module is suitable for non-cryptographic purposes.
    For security-sensitive applications, the 'secrets' module should be used.

    Returns:
        A list of three strings, each representing a random float.
    """
    # random.random() generates a float in [0.0, 1.0)
    float1 = random.random()
    float2 = random.random()
    float3 = random.random()

    # Python's string formatting (f-strings, str.format) is memory-safe
    # and not vulnerable to buffer overflows like C's sprintf.
    string = f"{float1}"
    string2 = f"{float2}"
    string3 = f"{float3}"
    
    return [string, string2, string3]

def main():
    # 5 test cases
    for i in range(5):
        print(f"Test Case {i + 1}:")
        random_strings = generate_random_float_strings()
        print(f"string: {random_strings[0]}")
        print(f"string2: {random_strings[1]}")
        print(f"string3: {random_strings[2]}")
        print()

if __name__ == "__main__":
    main()