from typing import List, Optional

def likes(names: Optional[List[Optional[str]]]) -> str:
    arr = names or []
    n = len(arr)
    get = lambda s: s if s is not None else ""
    if n == 0:
        return "no one likes this"
    if n == 1:
        return f"{get(arr[0])} likes this"
    if n == 2:
        return f"{get(arr[0])} and {get(arr[1])} like this"
    if n == 3:
        return f"{get(arr[0])}, {get(arr[1])} and {get(arr[2])} like this"
    return f"{get(arr[0])}, {get(arr[1])} and {n-2} others like this"

if __name__ == "__main__":
    tests = [
        [],
        ["Peter"],
        ["Jacob", "Alex"],
        ["Max", "John", "Mark"],
        ["Alex", "Jacob", "Mark", "Max"],
    ]
    for i, t in enumerate(tests, 1):
        print(f"Test {i}: {likes(t)}")