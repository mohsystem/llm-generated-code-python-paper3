
def is_isogram(s):
    if not s:
        return True
    
    lower_str = s.lower()
    char_set = set()
    
    for char in lower_str:
        if char in char_set:
            return False
        char_set.add(char)
    
    return True


if __name__ == "__main__":
    # Test cases
    print(f"Test 1: 'Dermatoglyphics' -> {is_isogram('Dermatoglyphics')}")
    print(f"Test 2: 'aba' -> {is_isogram('aba')}")
    print(f"Test 3: 'moOse' -> {is_isogram('moOse')}")
    print(f"Test 4: '' -> {is_isogram('')}")
    print(f"Test 5: 'isogram' -> {is_isogram('isogram')}")
