from typing import List, Dict


def two_sum(numbers: List[int], target: int) -> List[int]:
    if not isinstance(numbers, list) or len(numbers) < 2:
        raise ValueError("Input array must be a list with length >= 2.")
    seen: Dict[int, int] = {}
    for idx, val in enumerate(numbers):
        complement = target - val
        if complement in seen:
            return [seen[complement], idx]
        if val not in seen:
            seen[val] = idx
    raise ValueError("No two sum solution found.")


def _run_test(nums: List[int], target: int) -> None:
    try:
        res = two_sum(nums, target)
        print(f"Input: {nums}, target={target} -> {res}")
    except ValueError as e:
        print(f"Error: {e}")


def main() -> None:
    _run_test([1, 2, 3], 4)              # expected [0,2]
    _run_test([3, 2, 4], 6)              # expected [1,2]
    _run_test([3, 3], 6)                 # expected [0,1]
    _run_test([-1, -2, -3, -4, -5], -8)  # expected [2,4]
    _run_test([0, 4, 3, 0], 0)           # expected [0,3]


if __name__ == "__main__":
    main()