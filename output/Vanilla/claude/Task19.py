
def spin_words(sentence):
    words = sentence.split(" ")
    result = []
    
    for word in words:
        if len(word) >= 5:
            result.append(word[::-1])
        else:
            result.append(word)
    
    return " ".join(result)

if __name__ == "__main__":
    # Test case 1
    print(spin_words("Hey fellow warriors"))
    
    # Test case 2
    print(spin_words("This is a test"))
    
    # Test case 3
    print(spin_words("This is another test"))
    
    # Test case 4
    print(spin_words("Welcome"))
    
    # Test case 5
    print(spin_words("Hi"))
