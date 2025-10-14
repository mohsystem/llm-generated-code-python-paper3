# Step 1: Problem understanding
# Find the lowest index N where sum of left elements equals sum of right elements.

# Step 2-3: Security requirements and Secure coding generation
# - Pure function, no side effects.
# - Python ints have arbitrary precision, safe from overflow.

def find_even_index(arr):
    if arr is None:
        return -1
    total = sum(arr)
    left = 0
    for i, v in enumerate(arr):
        right = total - left - v
        if left == right:
            return i
        left += v
    return -1

# Step 4: Code review
# - Uses O(n) time, O(1) space.
# - Handles empty and None.

# Step 5: Secure code output
def main():
    tests = [
        [1, 2, 3, 4, 3, 2, 1],         # expected 3
        [1, 100, 50, -51, 1, 1],       # expected 1
        [20, 10, -80, 10, 10, 15, 35], # expected 0
        [1, 2, 3, 4, 5, 6],            # expected -1
        [2, 0, 2],                     # expected 1
    ]
    for i, t in enumerate(tests, 1):
        res = find_even_index(t)
        print(f"Test {i} {t} => {res}")

if __name__ == "__main__":
    main()