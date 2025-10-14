# Chain-of-Through Step 1: Problem understanding
# Implement accum(s) producing "A-Bb-Ccc-..."; letters only.

# Chain-of-Through Step 2: Security requirements
# - Pure function; no I/O side-effects.
# - Handle None and empty string.

# Chain-of-Through Step 3: Secure coding generation
def accum(s: str) -> str:
    if s is None:
        return None
    # Step 4: Review - Python join and comprehension are safe and bounded.
    return "-".join(ch.upper() + ch.lower() * i for i, ch in enumerate(s))

# Step 5: Secure code output - tests
if __name__ == "__main__":
    tests = [
        "abcd",
        "RqaEzty",
        "cwAt",
        "",
        "ZpglnRxqenU",
    ]
    for t in tests:
        print(f'accum("{t}") -> "{accum(t)}"')