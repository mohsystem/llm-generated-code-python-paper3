def build_tower(n: int):
    if n <= 0:
        return []
    width = 2 * n - 1
    result = []
    for i in range(1, n + 1):
        stars = 2 * i - 1
        spaces = (width - stars) // 2
        result.append(' ' * spaces + '*' * stars + ' ' * spaces)
    return result


def _print_tower(tower):
    for line in tower:
        print(line)


def main():
        tests = [1, 2, 3, 6, 0]
        for n in tests:
            print(f"n = {n}")
            _print_tower(build_tower(n))
            print()


if __name__ == "__main__":
    main()