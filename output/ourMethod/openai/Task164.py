from typing import List, Tuple

def last_name_len_sort(names: List[str]) -> List[str]:
    if not isinstance(names, list):
        raise ValueError("Input must be a list of strings.")
    processed: List[Tuple[int, str, int, str]] = []
    for idx, n in enumerate(names):
        if not isinstance(n, str):
            raise ValueError(f"Name at index {idx} is not a string.")
        t = n.strip()
        last_space = t.rfind(" ")
        if last_space <= 0 or last_space >= len(t) - 1:
            raise ValueError(f"Invalid name format (must contain first and last name): {n!r}")
        last = t[last_space + 1 :]
        processed.append((len(last), last.lower(), idx, n))
    # Sort by length of last name, then alphabetical by last name (case-insensitive), then by original index
    processed.sort(key=lambda x: (x[0], x[1], x[2]))
    return [x[3] for x in processed]

def _print_list(lst: List[str]) -> None:
    print(lst)

if __name__ == "__main__":
    tests = [
        [
            "Jennifer Figueroa",
            "Heather Mcgee",
            "Amanda Schwartz",
            "Nicole Yoder",
            "Melissa Hoffman",
        ],
        [
            "Jim Bo",
            "Ana Li",
            "Zoe Wu",
            "Tom Ng",
            "Foo Bar",
        ],
        [
            "Mary Jane Watson",
            "Jean Claude Van Damme",
            "Peter Parker",
            "Tony Stark",
            "Bruce Wayne",
        ],
        [
            "  Alice   Smith  ",
            "bob a",
            "CARL B",
            "dave  aa",
            "Eve   Z",
        ],
        [
            "Alice Hope",
            "Bob Hope",
            "Carl Hope",
            "Ann Hope",
            "Zed Hope",
        ],
    ]
    for i, t in enumerate(tests, 1):
        res = last_name_len_sort(t)
        print(f"Test {i}: ", end="")
        _print_list(res)