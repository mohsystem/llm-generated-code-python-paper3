# Step 1: Problem understanding:
# - Read a numeric value from command line, add 1000, and print the result.
# - Provide a function add1000 that accepts input and returns output.

# Step 2: Security requirements:
# - Validate input and handle parsing errors.
# - Python ints are unbounded, so overflow is not a concern, but we still validate input.

# Step 3: Secure coding generation:
# - Use int() conversion with try/except for validation.

# Step 4: Code review:
# - Ensure robust handling of missing/invalid input.

# Step 5: Secure code output:
import sys

def add1000(value: int) -> int:
    return int(value) + 1000

if __name__ == "__main__":
    if len(sys.argv) >= 2:
        try:
            v = int(sys.argv[1].strip())
            print(add1000(v))
        except (ValueError, TypeError):
            print("Invalid integer input.", file=sys.stderr)
    else:
        tests = [0, 42, -42, 9223372036854775807 - 1000, -9223372036854775808 + 1000]
        for t in tests:
            print(f"add1000({t}) = {add1000(t)}")