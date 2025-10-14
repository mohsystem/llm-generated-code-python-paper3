
def highest_scoring_word(s):
    words = s.split(" ")
    highest_word = ""
    highest_score = 0
    
    for word in words:
        score = sum(ord(c) - ord('a') + 1 for c in word)
        if score > highest_score:
            highest_score = score
            highest_word = word
    
    return highest_word


if __name__ == "__main__":
    # Test case 1
    print(highest_scoring_word("man i need a taxi up to ubud"))
    
    # Test case 2
    print(highest_scoring_word("what time are we climbing up the volcano"))
    
    # Test case 3
    print(highest_scoring_word("take me to semynak"))
    
    # Test case 4
    print(highest_scoring_word("aa b"))
    
    # Test case 5
    print(highest_scoring_word("abad"))
