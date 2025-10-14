import collections
import sys
from typing import List

# This is the Master's API interface.
# You should not implement it, or speculate about its implementation.
class Master:
    def __init__(self, secret: str, words: List[str], allowed_guesses: int):
        self._secret = secret
        self._word_set = set(words)
        self._allowed_guesses = allowed_guesses
        self._guesses_made = 0
        self._found = False

    def guess(self, word: str) -> int:
        self._guesses_made += 1
        if word not in self._word_set:
            return -1
        
        matches = 0
        for i in range(len(self._secret)):
            if self._secret[i] == word[i]:
                matches += 1
        
        if matches == len(self._secret):
            self._found = True
        
        return matches

    def get_result(self) -> str:
        if self._found and self._guesses_made <= self._allowed_guesses:
            return "You guessed the secret word correctly."
        else:
            return "Either you took too many guesses, or you did not find the secret word."

def count_matches(w1: str, w2: str) -> int:
    return sum(c1 == c2 for c1, c2 in zip(w1, w2))

def findSecretWord(words: List[str], master: 'Master', allowedGuesses: int) -> None:
    candidates = list(words)
    
    for _ in range(allowedGuesses):
        if not candidates:
            return

        best_guess = ""
        min_max_group_size = sys.maxsize

        for w1 in words:
            groups = collections.defaultdict(int)
            for w2 in candidates:
                matches = count_matches(w1, w2)
                groups[matches] += 1
            
            if not groups: 
                continue
            max_group_size = max(groups.values())
            
            if max_group_size < min_max_group_size:
                min_max_group_size = max_group_size
                best_guess = w1

        matches = master.guess(best_guess)
        if matches == 6:
            return

        candidates = [c for c in candidates if count_matches(best_guess, c) == matches]

if __name__ == '__main__':
    # Test Case 1
    words1 = ["acckzz", "ccbazz", "eiowzz", "abcczz"]
    master1 = Master("acckzz", words1, 10)
    findSecretWord(words1, master1, 10)
    print(f"Test Case 1: {master1.get_result()}")

    # Test Case 2
    words2 = ["hamada", "khaled"]
    master2 = Master("hamada", words2, 10)
    findSecretWord(words2, master2, 10)
    print(f"Test Case 2: {master2.get_result()}")

    # Test Case 3
    words3 = ["aaaaaa", "bbbbbb", "cccccc", "dddddd", "eeeeee", "ffffff"]
    master3 = Master("aaaaaa", words3, 10)
    findSecretWord(words3, master3, 10)
    print(f"Test Case 3: {master3.get_result()}")

    # Test Case 4
    words4 = ["abacab", "abacba", "ababca", "ababac", "ababab", "bababa", "babacb", "bababc", "bacaba", "bacbab"]
    master4 = Master("abacab", words4, 10)
    findSecretWord(words4, master4, 10)
    print(f"Test Case 4: {master4.get_result()}")

    # Test Case 5
    words5 = ["abcdef", "zzzzzz", "aaaaaa", "bbbbbb", "cccccc", "dddddd", "eeeeee", "ffffff", "gggggg", "hhhhhh"]
    master5 = Master("zzzzzz", words5, 15)
    findSecretWord(words5, master5, 15)
    print(f"Test Case 5: {master5.get_result()}")