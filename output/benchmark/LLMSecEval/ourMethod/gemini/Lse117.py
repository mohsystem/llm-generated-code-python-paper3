import random
import os
from typing import Tuple

# Use SystemRandom for better randomness source (uses os.urandom)
sys_random = random.SystemRandom()

def float_to_string(f: float) -> str:
    """Converts a float to its string representation."""
    return str(f)

def generate_three_random_float_strings() -> Tuple[str, str, str]:
    """
    Generates three random floats and converts them to strings.
    
    Returns:
        A tuple of three strings.
    """
    # Generate three random floats
    a = sys_random.uniform(0.0, 1000.0)
    b = sys_random.uniform(0.0, 1000.0)
    c = sys_random.uniform(0.0, 1000.0)
    
    # Convert floats to strings using a helper function
    str_a = float_to_string(a)
    str_b = float_to_string(b)
    str_c = float_to_string(c)
    
    return str_a, str_b, str_c

def main():
    """Main function to run test cases."""
    print("Running 5 test cases...")
    for i in range(5):
        print(f"\n--- Test Case {i + 1} ---")
        str_a, str_b, str_c = generate_three_random_float_strings()
        print(f"str_a: {str_a}")
        print(f"str_b: {str_b}")
        print(f"str_c: {str_c}")

if __name__ == "__main__":
    main()