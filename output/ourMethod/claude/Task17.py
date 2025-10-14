
def to_jaden_case(phrase: str) -> str:
    if phrase is None or phrase == "":
        return None
    
    result = []
    capitalize_next = True
    
    for char in phrase:
        if char.isspace():
            result.append(char)
            capitalize_next = True
        elif capitalize_next and char.isalpha():
            result.append(char.upper())
            capitalize_next = False
        else:
            result.append(char)
    
    return ''.join(result)


def main():
    test_cases = [
        "How can mirrors be real if our eyes aren't real",
        "hello world",
        "i love python programming",
        "it's a beautiful day",
        None
    ]
    
    for i, test in enumerate(test_cases, 1):
        result = to_jaden_case(test)
        print(f"Test {i}: {result}")


if __name__ == "__main__":
    main()
