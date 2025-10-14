def solution(string, ending):
    """
    Returns true if the first argument(string) passed in ends with the 2nd argument (also a string).
    """
    return string.endswith(ending)

# main method with 5 test cases
if __name__ == '__main__':
    print("Test Case 1: solution('abc', 'bc')")
    print(f"Result: {solution('abc', 'bc')}")  # Expected: True

    print("\nTest Case 2: solution('abc', 'd')")
    print(f"Result: {solution('abc', 'd')}")  # Expected: False

    print("\nTest Case 3: solution('samurai', 'ai')")
    print(f"Result: {solution('samurai', 'ai')}")  # Expected: True
    
    print("\nTest Case 4: solution('abc', '')")
    print(f"Result: {solution('abc', '')}")  # Expected: True
    
    print("\nTest Case 5: solution('test', 'testing')")
    print(f"Result: {solution('test', 'testing')}")  # Expected: False