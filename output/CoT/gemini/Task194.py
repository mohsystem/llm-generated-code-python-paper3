import collections

# This is the Master's API interface.
# You should not implement it, or speculate about its implementation
class Master:
   def guess(self, word: str) -> int:
       pass

# Helper Master class for testing purposes
class MasterImpl(Master):
    def __init__(self, secret: str, words: list[str], allowed_guesses: int):
        self._secret = secret
        self._word_set = set(words)
        self._guess_count = 0
        self._allowed_guesses = allowed_guesses
        self._solved = False

    def guess(self, word: str) -> int:
        self._guess_count += 1
        if word not in self._word_set:
            return -1
        
        matches = 0
        for i in range(len(self._secret)):
            if self._secret[i] == word[i]:
                matches += 1
        
        if matches == len(self._secret):
            self._solved = True
        return matches
    
    def print_result(self):
        if self._solved and self._guess_count <= self._allowed_guesses:
            print("You guessed the secret word correctly.")
        else:
            print("Either you took too many guesses, or you did not find the secret word.")

def match(w1: str, w2: str) -> int:
    return sum(c1 == c2 for c1, c2 in zip(w1, w2))

def findSecretWord(words: list[str], master: 'Master', allowedGuesses: int):
    candidates = list(words)
    
    for _ in range(allowedGuesses):
        if not candidates:
            return

        # Minimax strategy: find the best word to guess
        best_guess = candidates[0]
        min_max_group_size = float('inf')

        for w1 in candidates:
            groups = collections.defaultdict(int)
            for w2 in candidates:
                groups[match(w1, w2)] += 1
            
            max_group_size = max(groups.values())
            if max_group_size < min_max_group_size:
                min_max_group_size = max_group_size
                best_guess = w1

        matches = master.guess(best_guess)

        if matches == 6:
            return

        candidates = [word for word in candidates if match(word, best_guess) == matches]

if __name__ == "__main__":
    # Test Case 1
    print("Test Case 1:")
    words1 = ["acckzz", "ccbazz", "eiowzz", "abcczz"]
    secret1 = "acckzz"
    allowedGuesses1 = 10
    master1 = MasterImpl(secret1, words1, allowedGuesses1)
    findSecretWord(words1, master1, allowedGuesses1)
    master1.print_result()

    # Test Case 2
    print("\nTest Case 2:")
    words2 = ["hamada", "khaled"]
    secret2 = "hamada"
    allowedGuesses2 = 10
    master2 = MasterImpl(secret2, words2, allowedGuesses2)
    findSecretWord(words2, master2, allowedGuesses2)
    master2.print_result()

    # Test Case 3
    print("\nTest Case 3:")
    words3 = ["rccqcb","acckzz","ccbazz","eiowzz","abcczz", "hamada", "bobson", "vrtrva"]
    secret3 = "bobson"
    allowedGuesses3 = 10
    master3 = MasterImpl(secret3, words3, allowedGuesses3)
    findSecretWord(words3, master3, allowedGuesses3)
    master3.print_result()
    
    # Test Case 4
    print("\nTest Case 4:")
    words4 = ["banana","cabana","banaba","bandan","banban","bonbon"]
    secret4 = "banana"
    allowedGuesses4 = 15
    master4 = MasterImpl(secret4, words4, allowedGuesses4)
    findSecretWord(words4, master4, allowedGuesses4)
    master4.print_result()
    
    # Test Case 5
    print("\nTest Case 5:")
    words5 = ["abcdef","abdfed","acbdef","aefdcb","abdcef","abcefd"]
    secret5 = "abcdef"
    allowedGuesses5 = 10
    master5 = MasterImpl(secret5, words5, allowedGuesses5)
    findSecretWord(words5, master5, allowedGuesses5)
    master5.print_result()