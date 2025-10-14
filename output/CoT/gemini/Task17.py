def to_jaden_case(string):
    """
    Converts a string to Jaden Case.
    """
    if not string:
        return ""
    # Use split() and capitalize() to correctly handle words and punctuation like apostrophes.
    return ' '.join(word.capitalize() for word in string.split(' '))

# main method with 5 test cases
if __name__ == '__main__':
    test_cases = [
        "How can mirrors be real if our eyes aren't real",
        "",
        "most trees are blue",
        "The Quick Brown Fox Jumps Over The Lazy Dog",
        "hello world"
    ]
    
    print("Python Test Cases:")
    for i, test in enumerate(test_cases):
        print(f"Test Case {i+1}:")
        print(f"  Original: \"{test}\"")
        print(f"  Jaden-Cased: \"{to_jaden_case(test)}\"\n")