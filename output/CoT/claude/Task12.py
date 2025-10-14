
def highest_scoring_word(s):
    if not s or not s.strip():
        return ""
    
    words = s.strip().split()
    highest_word = ""
    max_score = 0
    
    for word in words:
        score = calculate_score(word)
        if score > max_score:
            max_score = score
            highest_word = word
    
    return highest_word

def calculate_score(word):
    score = 0
    for c in word:
        if 'a' <= c <= 'z':
            score += ord(c) - ord('a') + 1
    return score

if __name__ == "__main__":
    print("Test 1:", highest_scoring_word("man i need a taxi up to ubud"))
    print("Test 2:", highest_scoring_word("what time are we climbing up the volcano"))
    print("Test 3:", highest_scoring_word("take me to semynak"))
    print("Test 4:", highest_scoring_word("aa b"))
    print("Test 5:", highest_scoring_word("a z"))
