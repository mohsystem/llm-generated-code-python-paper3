# Step 1: Problem understanding and definition
# Step 2: Security requirements consideration
# Step 3: Secure coding generation
# Step 4: Code review simulated through comments
# Step 5: Secure code output

def odd_or_even(arr):
    parity = 0  # 0 for even, 1 for odd
    if arr is not None:
        for n in arr:
            parity ^= (n & 1)  # safe for negatives
    return "even" if parity == 0 else "odd"

if __name__ == "__main__":
    tests = [
        [],              # even
        [0],             # even
        [0, 1, 4],       # odd
        [0, -1, -5],     # even
        [2, 2, 2, 2],    # even
    ]
    for t in tests:
        print(odd_or_even(t))