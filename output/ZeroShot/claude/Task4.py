
def is_isogram(s):
    if not s:
        return True
    
    lower_str = s.lower()
    
    for i in range(len(lower_str)):
        for j in range(i + 1, len(lower_str)):
            if lower_str[i] == lower_str[j]:
                return False
    
    return True

if __name__ == "__main__":
    # Test cases
    print(is_isogram("Dermatoglyphics"))  # True
    print(is_isogram("aba"))              # False
    print(is_isogram("moOse"))            # False
    print(is_isogram(""))                 # True
    print(is_isogram("isogram"))          # False
