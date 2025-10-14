def copy_string(s: str) -> str:
    return "" + s if s is not None else None

def concatenate(a: str, b: str) -> str:
    if a is None and b is None:
        return None
    if a is None:
        return "" + b
    if b is None:
        return "" + a
    return a + b

def reverse_string(s: str) -> str:
    return s[::-1] if s is not None else None

def to_upper_string(s: str) -> str:
    return s.upper() if s is not None else None

def remove_whitespace(s: str) -> str:
    if s is None:
        return None
    return "".join(ch for ch in s if not ch.isspace())

if __name__ == "__main__":
    t1 = "Hello"
    t2a = "Hello"
    t2b = " World"
    t3 = "OpenAI"
    t4 = "Mixed Case 123"
    t5 = "  a b\tc\nd  "

    print("Test 1 - copy_string:", copy_string(t1))
    print("Test 2 - concatenate:", concatenate(t2a, t2b))
    print("Test 3 - reverse_string:", reverse_string(t3))
    print("Test 4 - to_upper_string:", to_upper_string(t4))
    print("Test 5 - remove_whitespace:", remove_whitespace(t5))