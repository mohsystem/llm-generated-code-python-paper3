# Chain-of-Through Step 1: Problem understanding
# - Generate three random floats and convert them to strings similar to sprintf into variables: string, string2, string3.
# - Function must accept parameters and return output. Include 5 test cases.

# Chain-of-Through Step 2: Security requirements
# - Avoid global state; use a local Random instance via random.Random(seed).

# Chain-of-Through Step 3: Secure coding generation
# - Use deterministic seeding when provided.
# - Use sprintf-like formatting with "%.<precision>f".

# Chain-of-Through Step 4: Code review
# - No external IO or unsafe operations.

# Chain-of-Through Step 5: Secure code output
from typing import List, Optional

def generate_random_float_strings(seed: Optional[int], precision: int = 6) -> List[str]:
    import random
    rnd = random.Random(seed)
    f1 = rnd.random()
    f2 = rnd.random()
    f3 = rnd.random()
    fmt = "%." + str(max(0, precision)) + "f"
    string  = fmt % f1
    string2 = fmt % f2
    string3 = fmt % f3
    return [string, string2, string3]

if __name__ == "__main__":
    # 5 test cases
    tests = [
        (0, 6),
        (1, 4),
        (42, 2),
        (123456789, 8),
        (None, 6),
    ]
    for seed, prec in tests:
        result = generate_random_float_strings(seed, prec)
        print(f"seed={seed}, precision={prec} -> {result}")