
from typing import List

class Master:
    def guess(self, word: str) -> int:
        pass

class MockMaster(Master):
    def __init__(self, secret: str, words: List[str], allowed_guesses: int):
        if not secret or len(secret) != 6:
            raise ValueError("Secret must be 6 characters")
        self.secret = secret
        self.guess_count = 0
        self.allowed_guesses = allowed_guesses
        self.word_set = set(words)
        if secret not in self.word_set:
            raise ValueError("Secret must be in words")
    
    def guess(self, word: str) -> int:
        if not word or len(word) != 6:
            return -1
        self.guess_count += 1
        if self.guess_count > self.allowed_guesses:
            return -1
        if word not in self.word_set:
            return -1
        
        matches = sum(1 for i in range(6) if word[i] == self.secret[i])
        return matches
    
    def is_success(self) -> bool:
        return self.guess_count <= self.allowed_guesses

def calculate_matches(word1: str, word2: str) -> int:
    if not word1 or not word2 or len(word1) != 6 or len(word2) != 6:
        return 0
    return sum(1 for i in range(6) if word1[i] == word2[i])

def findSecretWord(words: List[str], master: Master) -> None:
    if not words:
        return
    
    candidates = [word for word in words if word and len(word) == 6]
    
    if not candidates:
        return
    
    max_guesses = 10
    guess_count = 0
    
    while candidates and guess_count < max_guesses:
        guess = candidates[0]
        matches = master.guess(guess)
        guess_count += 1
        
        if matches == 6:
            return
        
        candidates = [
            candidate for candidate in candidates
            if calculate_matches(guess, candidate) == matches
        ]

def main():
    words1 = ["acckzz", "ccbazz", "eiowzz", "abcczz"]
    master1 = MockMaster("acckzz", words1, 10)
    findSecretWord(words1, master1)
    print("Test 1 Passed" if master1.is_success() else "Test 1 Failed")
    
    words2 = ["hamada", "khaled"]
    master2 = MockMaster("hamada", words2, 10)
    findSecretWord(words2, master2)
    print("Test 2 Passed" if master2.is_success() else "Test 2 Failed")
    
    words3 = ["gaxckt", "trlccr", "jxwhkz", "ycbfps", "peayuf", "yiejjw"]
    master3 = MockMaster("gaxckt", words3, 10)
    findSecretWord(words3, master3)
    print("Test 3 Passed" if master3.is_success() else "Test 3 Failed")
    
    words4 = ["abcdef"]
    master4 = MockMaster("abcdef", words4, 10)
    findSecretWord(words4, master4)
    print("Test 4 Passed" if master4.is_success() else "Test 4 Failed")
    
    words5 = ["ccbazz", "eiowzz", "abcczz", "acckzz"]
    master5 = MockMaster("acckzz", words5, 10)
    findSecretWord(words5, master5)
    print("Test 5 Passed" if master5.is_success() else "Test 5 Failed")

if __name__ == "__main__":
    main()
