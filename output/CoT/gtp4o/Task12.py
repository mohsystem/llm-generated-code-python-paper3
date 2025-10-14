# Step 1: Problem understanding
# Implement function to find the highest scoring word based on letter positions.
# Step 2: Security requirements
# Handle None/empty inputs safely. Avoid dangerous operations, use straightforward loops.
# Step 3: Secure coding generation
# Step 4: Code review
# Step 5: Secure code output

def highest_scoring_word(s: str) -> str:
    if not s:
        return ""
    best_word = ""
    best_score = float("-inf")
    for word in s.split():
        score = 0
        for ch in word:
            if 'a' <= ch <= 'z':
                score += (ord(ch) - ord('a') + 1)
        if score > best_score:
            best_score = score
            best_word = word
    return best_word

if __name__ == "__main__":
    # 5 test cases
    tests = [
        "man i need a taxi up to ubud",
        "what time are we climbing up the volcano",
        "take me to semynak",
        "aa b",
        "zoo aaaa"
    ]
    for t in tests:
        print(highest_scoring_word(t))