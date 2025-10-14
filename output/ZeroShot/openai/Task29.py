def two_sum(numbers, target):
    if numbers is None or len(numbers) < 2:
        raise ValueError("Invalid input")
    seen = {}
    for i, num in enumerate(numbers):
        comp = target - num
        if comp in seen:
            return (seen[comp], i)
        if num not in seen:
            seen[num] = i
    raise ValueError("No two sum solution")

def _print_pair(p):
    print(f"{{{p[0]}, {p[1]}}}")

def main():
    _print_pair(two_sum([1, 2, 3], 4))          # {0, 2}
    _print_pair(two_sum([3, 2, 4], 6))          # {1, 2}
    _print_pair(two_sum([3, 3], 6))             # {0, 1}
    _print_pair(two_sum([-1, -2, -3, -4], -6))  # {1, 3} or valid
    _print_pair(two_sum([2, 7, 11, 15], 9))     # {0, 1}

if __name__ == "__main__":
    main()