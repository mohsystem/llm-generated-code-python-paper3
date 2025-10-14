def find_missing_letter(arr):
    if arr is None or len(arr) < 2:
        raise ValueError("Input array must have at least 2 characters.")
    if not all(isinstance(c, str) and len(c) == 1 for c in arr):
        raise ValueError("All elements must be single-character strings.")
    is_lower = arr[0].islower()
    is_upper = arr[0].isupper()
    if not (is_lower or is_upper):
        raise ValueError("Input must contain alphabetic characters.")
    for c in arr:
        if not c.isalpha():
            raise ValueError("Input must contain only letters.")
        if (is_lower and not c.islower()) or (is_upper and not c.isupper()):
            raise ValueError("All letters must be in the same case.")

    expected = ord(arr[0]) + 1
    for i in range(1, len(arr)):
        if ord(arr[i]) != expected:
            return chr(expected)
        expected += 1
    raise ValueError("No missing letter found.")


if __name__ == "__main__":
    tests = [
        ['a','b','c','d','f'],  # -> 'e'
        ['O','Q','R','S'],      # -> 'P'
        ['m','n','p','q'],      # -> 'o'
        ['A','B','C','E'],      # -> 'D'
        ['t','v']               # -> 'u'
    ]
    for t in tests:
        missing = find_missing_letter(t)
        print(f"Missing: '{missing}'")