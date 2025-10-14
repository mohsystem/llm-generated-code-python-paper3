def build_tower(n):
    if n <= 0:
        return []
    width = 2 * n - 1
    return [(' ' * (n - i)) + ('*' * (2 * i - 1)) + (' ' * (n - i)) for i in range(1, n + 1)]

if __name__ == "__main__":
    tests = [1, 2, 3, 4, 6]
    for t in tests:
        print(f"Tower with {t} floors:")
        for row in build_tower(t):
            print(row)
        print()