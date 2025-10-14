from typing import List, Optional

class Task25:
    @staticmethod
    def number(lines: Optional[List[Optional[str]]]) -> List[str]:
        if lines is None:
            return []
        result: List[str] = []
        for i, s in enumerate(lines, start=1):
            safe = "" if s is None else str(s)
            result.append(f"{i}: {safe}")
        return result

if __name__ == "__main__":
    # Test case 1: empty list
    print(Task25.number([]))
    # Test case 2: ["a", "b", "c"]
    print(Task25.number(["a", "b", "c"]))
    # Test case 3: [None, "x", ""]
    print(Task25.number([None, "x", ""]))
    # Test case 4: ["only one"]
    print(Task25.number(["only one"]))
    # Test case 5: multiple lines
    print(Task25.number([f"line {i}" for i in range(5)]))