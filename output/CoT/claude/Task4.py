
def is_isogram(s):
    if s is None:
        return True
    
    lower_str = s.lower()
    seen_chars = set()
    
    for char in lower_str:
        if char.isalpha():
            if char in seen_chars:
                return False
            seen_chars.add(char)
    
    return True


if __name__ == "__main__":
    # Test case 1
    print(f"Test 1: 'Dermatoglyphics' -> {is_isogram('Dermatoglyphics')}")
    
    # Test case 2
    print(f"Test 2: 'aba' -> {is_isogram('aba')}")
    
    # Test case 3
    print(f"Test 3: 'moOse' -> {is_isogram('moOse')}")
    
    # Test case 4
    print(f"Test 4: '' -> {is_isogram('')}")
    
    # Test case 5
    print(f"Test 5: 'isogram' -> {is_isogram('isogram')}")
