from typing import List, Tuple
import sys

NAME_MIN_LEN = 1
NAME_MAX_LEN = 50
AGE_MIN = 0
AGE_MAX = 120
NUM_MIN = -1_000_000
NUM_MAX = 1_000_000
NUM_COUNT_MIN = 1
NUM_COUNT_MAX = 100
INPUT_MAX_LEN = 1024


def validate_name(raw: str) -> str:
    if raw is None:
        raise ValueError("Name is required.")
    trimmed = raw.strip()
    normalized = _collapse_spaces(trimmed)
    if not (NAME_MIN_LEN <= len(normalized) <= NAME_MAX_LEN):
        raise ValueError("Name must be between 1 and 50 characters after trimming.")
    for ch in normalized:
        if not (_is_ascii_letter(ch) or ch in " -'"):
            raise ValueError(f"Name contains invalid character: '{ch}'")
    return normalized


def _collapse_spaces(s: str) -> str:
    out = []
    prev_space = False
    for ch in s:
        if ch == ' ':
            if not prev_space:
                out.append(ch)
                prev_space = True
        else:
            out.append(ch)
            prev_space = False
    return ''.join(out)


def _is_ascii_letter(ch: str) -> bool:
    return ('A' <= ch <= 'Z') or ('a' <= ch <= 'z')


def validate_age(s: str) -> int:
    if s is None:
        raise ValueError("Age is required.")
    t = s.strip()
    if not t or len(t) > 3:
        raise ValueError("Age format invalid.")
    try:
        val = int(t, 10)
    except ValueError:
        raise ValueError("Age must be an integer.")
    if not (AGE_MIN <= val <= AGE_MAX):
        raise ValueError("Age must be between 0 and 120.")
    return val


def parse_numbers(s: str) -> List[int]:
    if s is None:
        raise ValueError("Numbers input is required.")
    t = s.strip()
    if not t:
        raise ValueError("Numbers input is empty.")
    # Split by commas and/or whitespace
    parts = [p for p in _split_tokens(t) if p]
    if not (NUM_COUNT_MIN <= len(parts) <= NUM_COUNT_MAX):
        raise ValueError("Provide between 1 and 100 numbers.")
    nums: List[int] = []
    for tok in parts:
        try:
            val = int(tok, 10)
        except ValueError:
            raise ValueError(f"Invalid integer: {tok}")
        if not (NUM_MIN <= val <= NUM_MAX):
            raise ValueError(f"Number out of range: {val}")
        nums.append(val)
    return nums


def _split_tokens(s: str) -> List[str]:
    tokens: List[str] = []
    curr = []
    for ch in s:
        if ch.isspace() or ch == ',':
            if curr:
                tokens.append(''.join(curr))
                curr = []
        else:
            curr.append(ch)
    if curr:
        tokens.append(''.join(curr))
    return tokens


def process_user_data(name: str, age: int, numbers: List[int]) -> str:
    if name is None:
        raise ValueError("Name is required.")
    if not (AGE_MIN <= age <= AGE_MAX):
        raise ValueError("Age out of range.")
    if numbers is None or not (NUM_COUNT_MIN <= len(numbers) <= NUM_COUNT_MAX):
        raise ValueError("Numbers count out of range.")
    for v in numbers:
        if not (NUM_MIN <= v <= NUM_MAX):
            raise ValueError(f"Number out of range: {v}")

    total = sum(numbers)
    mn = min(numbers)
    mx = max(numbers)
    evens = sum(1 for v in numbers if v % 2 == 0)
    odds = len(numbers) - evens
    avg = total / float(len(numbers))

    sorted_nums = sorted(numbers)
    n = len(sorted_nums)
    if n % 2 == 1:
        median = float(sorted_nums[n // 2])
    else:
        median = (sorted_nums[n // 2 - 1] + sorted_nums[n // 2]) / 2.0

    unique_sorted = sorted(set(numbers))
    unique_str = "[" + ", ".join(str(v) for v in unique_sorted) + "]"

    lines = []
    lines.append(f"Result for {name}")
    lines.append(f"Age next year: {age + 1}")
    lines.append(f"Count: {len(numbers)}, Min: {mn}, Max: {mx}, Sum: {total}, Average: {avg:.2f}, Median: {median:.2f}")
    lines.append(f"Evens: {evens}, Odds: {odds}")
    lines.append(f"Unique sorted: {unique_str}")
    return "\n".join(lines)


def _safe_input(prompt: str) -> str:
    print(prompt)
    line = sys.stdin.readline()
    if not line:
        raise ValueError("No input provided.")
    if len(line) > INPUT_MAX_LEN + 1:
        # +1 accounts for possible trailing newline
        raise ValueError("Input too long.")
    return line.rstrip("\n")


def main() -> None:
    # 5 test cases
    try:
        print("== Test Case 1 ==")
        print(process_user_data(validate_name("Alice"), 29, [1, 2, 3, 4, 5]))
    except Exception as e:
        print(f"Test 1 error: {e}")
    try:
        print("== Test Case 2 ==")
        print(process_user_data(validate_name("Bob O'Neil"), 0, [-10, 0, 10, 10]))
    except Exception as e:
        print(f"Test 2 error: {e}")
    try:
        print("== Test Case 3 ==")
        print(process_user_data(validate_name("Charles-John"), 120, [1_000_000, -1_000_000]))
    except Exception as e:
        print(f"Test 3 error: {e}")
    try:
        print("== Test Case 4 ==")
        print(process_user_data(validate_name("  Mary   Jane  "), 45, [2, 2, 2, 3, 3, 4]))
    except Exception as e:
        print(f"Test 4 error: {e}")
    try:
        print("== Test Case 5 ==")
        print(process_user_data(validate_name("D'Artagnan"), 35, [7, 7, 7, 7, 7]))
    except Exception as e:
        print(f"Test 5 error: {e}")

    # Interactive section
    try:
        name_line = _safe_input("Enter name (letters, spaces, hyphen, apostrophe; 1-50 chars):")
        name = validate_name(name_line)

        age_line = _safe_input("Enter age (0-120):")
        age = validate_age(age_line)

        nums_line = _safe_input("Enter up to 100 integers between -1000000 and 1000000, separated by spaces or commas:")
        numbers = parse_numbers(nums_line)

        result = process_user_data(name, age, numbers)
        print(result)
    except Exception as e:
        print(f"Input error: {e}")


if __name__ == "__main__":
    main()