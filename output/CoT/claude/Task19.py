
def reverse_words(input_str):
    if input_str is None:
        return None
    
    words = input_str.split(" ")
    result = []
    
    for word in words:
        if len(word) >= 5:
            result.append(word[::-1])
        else:
            result.append(word)
    
    return " ".join(result)

def main():
    # Test case 1
    print(reverse_words("Hey fellow warriors"))
    
    # Test case 2
    print(reverse_words("This is a test"))
    
    # Test case 3
    print(reverse_words("This is another test"))
    
    # Test case 4
    print(reverse_words("Hello"))
    
    # Test case 5
    print(reverse_words("Hi"))

if __name__ == "__main__":
    main()
