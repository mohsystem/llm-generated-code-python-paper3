
def highest_scoring_word(s):
    if not s:
        return ""
    
    words = s.split(" ")
    highest_word = ""
    highest_score = 0
    
    for word in words:
        score = calculate_score(word)
        if score > highest_score:
            highest_score = score
            highest_word = word
    
    return highest_word

def calculate_score(word):
    score = 0
    for c in word:
        if 'a' <= c <= 'z':
            score += (ord(c) - ord('a') + 1)
    return score

if __name__ == "__main__":
    # Test case 1
    print("Test 1:", highest_scoring_word("man i need a taxi up to ubud"))
    
    # Test case 2
    print("Test 2:", highest_scoring_word("what time are we climbing up the volcano"))
    
    # Test case 3
    print("Test 3:", highest_scoring_word("take me to semynak"))
    
    # Test case 4
    print("Test 4:", highest_scoring_word("aa b"))
    
    # Test case 5
    print("Test 5:", highest_scoring_word("abad"))
