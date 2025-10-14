
def reverse_words(s):
    if not s:
        return s
    
    words = s.split(' ')
    result = []
    
    for word in words:
        if len(word) >= 5:
            result.append(word[::-1])
        else:
            result.append(word)
    
    return ' '.join(result)


if __name__ == "__main__":
    # Test cases
    print("Test 1:", reverse_words("Hey fellow warriors"))
    print("Expected: Hey wollef sroirraw")
    print()
    
    print("Test 2:", reverse_words("This is a test"))
    print("Expected: This is a test")
    print()
    
    print("Test 3:", reverse_words("This is another test"))
    print("Expected: This is rehtona test")
    print()
    
    print("Test 4:", reverse_words("abcde"))
    print("Expected: edcba")
    print()
    
    print("Test 5:", reverse_words("a b c d"))
    print("Expected: a b c d")
