# Chain-of-Through process in code generation:
# 1) Problem understanding: Function returns value at provided index from id_sequence; also prompt-based variant.
# 2) Security requirements: Validate inputs; avoid exceptions from bad indices or parsing.
# 3) Secure coding generation: Bounds checks and safe parsing.
# 4) Code review: Ensure no out-of-bounds access; handle EOF and invalid input.
# 5) Secure code output: Return -1 for invalid cases.

from typing import List

def get_value_at_index(id_sequence: List[int], index: int) -> int:
    if id_sequence is None:
        return -1
    if index < 0 or index >= len(id_sequence):
        return -1
    return id_sequence[index]

def prompt_and_get_value(id_sequence: List[int]) -> int:
    try:
        raw = input("Enter index: ").strip()
    except EOFError:
        return -1
    if not raw:
        return -1
    try:
        idx = int(raw)
    except ValueError:
        return -1
    return get_value_at_index(id_sequence, idx)

if __name__ == "__main__":
    id_sequence = [10, 20, 30, 40, 50]

    test_indices = [0, 2, 4, 1, 3]
    for idx in test_indices:
        result = get_value_at_index(id_sequence, idx)
        print(f"Index {idx} -> {result}")

    # Uncomment to test interactive prompt:
    # user_result = prompt_and_get_value(id_sequence)
    # print(f"User-selected value -> {user_result}")