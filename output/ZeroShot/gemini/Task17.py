import os

def to_jaden_case(phrase):
    """
    Converts a string to Jaden Case.
    """
    if not phrase:
        return ""
    
    # Securely split words and capitalize them
    # This avoids issues with multiple spaces and leading/trailing spaces
    words = phrase.split()
    capitalized_words = []
    for word in words:
        if word: # Ensure the word is not an empty string
            capitalized_words.append(word[0].upper() + word[1:])
            
    return " ".join(capitalized_words)

# main method with 5 test cases
if __name__ == '__main__':
    # Test Case 1
    test1 = "How can mirrors be real if our eyes aren't real"
    print(f"Original: {test1}")
    print(f"Jaden-Cased: {to_jaden_case(test1)}")

    # Test Case 2
    test2 = "most trees are blue"
    print(f"\nOriginal: {test2}")
    print(f"Jaden-Cased: {to_jaden_case(test2)}")

    # Test Case 3
    test3 = ""
    print(f"\nOriginal: \"{test3}\"")
    print(f"Jaden-Cased: \"{to_jaden_case(test3)}\"")

    # Test Case 4
    test4 = "a b c d"
    print(f"\nOriginal: {test4}")
    print(f"Jaden-Cased: {to_jaden_case(test4)}")
    
    # Test Case 5
    test5 = "if a book store never runs out of a certain book, does that mean that nobody reads it, or everybody reads it"
    print(f"\nOriginal: {test5}")
    print(f"Jaden-Cased: {to_jaden_case(test5)}")